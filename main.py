# -*- coding: utf-8 -*-
import socket
import threading
import json
import os
import argparse
import ssl
import stat

# --- استيراد من الملف المشترك ---
from common_utils import send_msg, recv_msg, recvall, DEFAULT_PORT, BUFFER_SIZE, DEFAULT_CERT_FILE

# --- Constants الخاصة بالخادم ---
DEFAULT_KEY_FILE = "server.key"
DEFAULT_SHARE_DIR = "./server_share"

# --- Server Helper Functions ---
# (نفس الدوال list_directory_safely و send_file_from_server من الكود المدمج)
def list_directory_safely(base_share_path, requested_rel_path="."):
    try:
        safe_rel_path = os.path.normpath(requested_rel_path)
        if safe_rel_path.startswith("/") or safe_rel_path.startswith(".."):
             return None, "Invalid relative path format."

        full_path = os.path.abspath(os.path.join(base_share_path, safe_rel_path))

        if os.path.commonprefix([full_path, base_share_path]) != base_share_path:
            print(f"[!] Security Alert: Path traversal attempt! Req: '{requested_rel_path}', Res: '{full_path}'")
            return None, "Access denied: Path traversal attempt."

        if not os.path.isdir(full_path):
            return None, "Path is not a valid directory."

        items = []
        for item_name in os.listdir(full_path):
            item_path = os.path.join(full_path, item_name)
            item_info = {'name': item_name}
            try:
                stat_info = os.lstat(item_path) # Use lstat to avoid following links
                if stat.S_ISDIR(stat_info.st_mode): item_info['type'] = 'dir'; item_info['size'] = 0
                elif stat.S_ISREG(stat_info.st_mode): item_info['type'] = 'file'; item_info['size'] = stat_info.st_size
                elif stat.S_ISLNK(stat_info.st_mode): item_info['type'] = 'link'; item_info['size'] = stat_info.st_size
                else: item_info['type'] = 'other'; item_info['size'] = stat_info.st_size
                items.append(item_info)
            except OSError as e: print(f"[!] Error accessing item '{item_path}': {e}")

        current_rel_path = os.path.relpath(full_path, base_share_path)
        if current_rel_path == "..": current_rel_path = "." # Adjust if we are exactly at the root

        return items, current_rel_path

    except FileNotFoundError: return None, "Directory not found."
    except OSError as e: print(f"[!] FS error listing '{requested_rel_path}': {e}"); return None, f"Server filesystem error: {e}"
    except Exception as e: print(f"[!] Unexpected error in list_dir: {e}"); return None, "Unexpected server error."


def send_file_from_server(ssl_conn, base_share_path, requested_rel_path):
    """يرسل ملفًا من الخادم إلى العميل بأمان."""
    full_path = None # Initialize to avoid UnboundLocalError in finally
    try:
        safe_rel_path = os.path.normpath(requested_rel_path)
        if safe_rel_path.startswith("/") or safe_rel_path.startswith(".."):
             return False, "Invalid file path format."

        full_path = os.path.abspath(os.path.join(base_share_path, safe_rel_path))

        if os.path.commonprefix([full_path, base_share_path]) != base_share_path:
            print(f"[!] Security Alert: Path traversal download! Req: '{requested_rel_path}'")
            send_msg(ssl_conn, json.dumps({'type': 'error', 'message': 'Access denied: Path traversal attempt.'}).encode('utf-8'))
            return False, "Path traversal attempt."

        if not os.path.isfile(full_path):
             msg = 'Requested path is not a regular file.' if os.path.lexists(full_path) else 'File not found.'
             send_msg(ssl_conn, json.dumps({'type': 'error', 'message': msg}).encode('utf-8'))
             return False, msg

        filesize = os.path.getsize(full_path)
        filename = os.path.basename(full_path)

        # 1. Send file info
        file_info = {'type': 'file_info', 'filename': filename, 'filesize': filesize}
        print(f"[*] Sending file info (DOWNLOAD): {filename} ({filesize} bytes)")
        if not send_msg(ssl_conn, json.dumps(file_info).encode('utf-8')):
            return False, "Network error sending file info."

        # 2. Send file data
        print(f"[*] Sending file data (DOWNLOAD): {filename}...")
        bytes_sent = 0
        f = open(full_path, 'rb') # Open file before loop
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk: break
            if not send_msg(ssl_conn, chunk):
                 print(f"\n[!] Failed sending DOWNLOAD chunk for {filename} at {bytes_sent}.")
                 # No reliable way to signal error to client here if send failed
                 return False, "Network error sending chunk."
            bytes_sent += len(chunk)
            print(f"    Sent DOWNLOAD {bytes_sent}/{filesize} bytes", end='\r')
        print(f"\n[+] File data (DOWNLOAD) for '{filename}' sent completely.")
        return True, "File sent successfully."

    except FileNotFoundError:
         # This case should be caught by isfile check earlier, but handle defensively
         print(f"[!] File not found error during send_file: {requested_rel_path}")
         send_msg(ssl_conn, json.dumps({'type': 'error', 'message': 'File not found on server.'}).encode('utf-8'))
         return False, "File not found on server."
    except IOError as e: # Includes permission errors
        print(f"\n[!] IO Error reading file '{requested_rel_path}': {e}")
        send_msg(ssl_conn, json.dumps({'type': 'error', 'message': f'Server IO error reading file: {e}'}).encode('utf-8'))
        return False, f"IO error reading file: {e}"
    except Exception as e:
         print(f"\n[!] Unexpected error sending file {requested_rel_path}: {e}")
         # Try to send a generic error if possible
         try:
            send_msg(ssl_conn, json.dumps({'type': 'error', 'message': 'Unexpected server error during file transfer.'}).encode('utf-8'))
         except: pass # Ignore errors trying to send error message
         return False, f"Unexpected error sending file: {e}"
    finally:
         if 'f' in locals() and f and not f.closed:
             f.close()


# --- Server Main Logic ---
# (نفس الدالة handle_client من الكود المدمج، مع التأكد من استخدام الدوال المستوردة)
def handle_client(ssl_conn, addr, base_share_path_abs):
    client_name = f"{addr}"
    print(f"[+] Accepted SSL connection from {addr}")

    # Receive identity
    initial_data_result = recv_msg(ssl_conn)
    if isinstance(initial_data_result, MemoryError):
         print(f"[!] Memory error receiving identity from {addr}: {initial_data_result}. Closing.")
         return
    if initial_data_result is None:
         print(f"[!] Failed to receive identity from {addr}. Closing.")
         return

    initial_data = initial_data_result

    try:
        identity_msg = json.loads(initial_data.decode('utf-8'))
        if identity_msg.get('type') == 'identity':
            received_name = identity_msg.get('name', '').strip()
            if received_name: client_name = f"{received_name}@{addr}"
            print(f"[*] Client identified as: {client_name}")
        else: print(f"[!] Expected identity first from {addr}. Using IP.")
    except (json.JSONDecodeError, UnicodeDecodeError): print(f"[!] Invalid identity msg from {addr}. Using IP.")

    # Main message loop
    while True:
        decrypted_data_result = recv_msg(ssl_conn)
        if isinstance(decrypted_data_result, MemoryError):
            print(f"[!] Memory error receiving data from {client_name}: {decrypted_data_result}. Closing.")
            # Attempt to notify client (best effort)
            send_msg(ssl_conn, json.dumps({'type':'error', 'message':'Server memory limit exceeded receiving your message.'}).encode('utf-8'))
            break
        if decrypted_data_result is None:
            print(f"[-] Connection closed or receive error for {client_name}")
            break

        decrypted_data = decrypted_data_result

        try:
            message = json.loads(decrypted_data.decode('utf-8'))
            msg_type = message.get('type')
            print(f"[*] Received from {client_name}: Type={msg_type}")

            if msg_type == 'message':
                print(f"  -> Message: {message.get('payload')}")

            elif msg_type == 'file_info': # UPLOAD to server
                filename = message.get('filename')
                filesize = message.get('filesize')
                if not filename or filesize is None:
                     print("[!] Invalid file_info received (missing fields).")
                     send_msg(ssl_conn, json.dumps({'type':'error', 'message':'Invalid file info received.'}).encode('utf-8'))
                     continue # Skip this message

                print(f"  -> Receiving file info (UPLOAD): {filename} ({filesize} bytes)")
                os.makedirs(base_share_path_abs, exist_ok=True)
                safe_filename = os.path.basename(filename)
                filepath = os.path.join(base_share_path_abs, safe_filename)

                confirm_start = {'status': 'ready_for_upload', 'filename': safe_filename}
                if not send_msg(ssl_conn, json.dumps(confirm_start).encode('utf-8')):
                     print(f"[!] Failed 'ready_for_upload' confirmation to {client_name}")
                     break

                print(f"  -> Receiving UPLOAD data for {safe_filename}...")
                bytes_received = 0
                try:
                    with open(filepath, 'wb') as f:
                        while bytes_received < filesize:
                            file_chunk_result = recv_msg(ssl_conn)
                            if isinstance(file_chunk_result, MemoryError): raise file_chunk_result # Propagate memory error
                            if file_chunk_result is None: raise ConnectionAbortedError("Upload transfer interrupted by client or network.")
                            file_chunk_decrypted = file_chunk_result
                            f.write(file_chunk_decrypted)
                            bytes_received += len(file_chunk_decrypted)
                            print(f"     Rcvd UPLOAD {bytes_received}/{filesize} bytes", end='\r')
                    print(f"\n[+] UPLOAD '{safe_filename}' OK from {client_name}.")
                    confirm_done = {'status': 'upload_received', 'filename': safe_filename}
                    send_msg(ssl_conn, json.dumps(confirm_done).encode('utf-8'))
                except (ConnectionAbortedError, IOError, MemoryError) as e:
                     print(f"\n[!] Error during UPLOAD reception for {safe_filename}: {e}")
                     if os.path.exists(filepath) and 'bytes_received' in locals() and bytes_received < filesize:
                         try: os.remove(filepath); print(f"  -> Removed incomplete UPLOAD: {filepath}")
                         except OSError as e_rem: print(f"[!] Error removing incomplete UPLOAD {filepath}: {e_rem}")
                     # If memory error, we might already have notified, otherwise try now
                     if not isinstance(e, MemoryError):
                         send_msg(ssl_conn, json.dumps({'type':'error', 'message':f'Server error during upload: {e}'}).encode('utf-8'))
                     break # Stop handling this client

            elif msg_type == 'list_dir':
                requested_path = message.get('path', '.')
                print(f"  -> Request to list directory: '{requested_path}'")
                items, current_rel_path_or_error = list_directory_safely(base_share_path_abs, requested_path)
                if items is not None:
                    response = {'type': 'dir_listing', 'path': current_rel_path_or_error, 'items': items}
                else:
                    response = {'type': 'error', 'message': f"List failed '{requested_path}': {current_rel_path_or_error}"}
                if not send_msg(ssl_conn, json.dumps(response).encode('utf-8')): break # Stop if send fails

            elif msg_type == 'download_file':
                requested_filepath = message.get('filepath')
                if requested_filepath:
                    print(f"  -> Request to download file: '{requested_filepath}'")
                    success, status_msg = send_file_from_server(ssl_conn, base_share_path_abs, requested_filepath)
                    print(f"  -> Download attempt status for '{requested_filepath}': {status_msg}")
                    # If send_file_from_server failed due to network error sending chunk,
                    # the connection might be broken, loop will likely exit on next recv_msg.
                else:
                     print("[!] Client requested download without filepath.")
                     send_msg(ssl_conn, json.dumps({'type': 'error', 'message': 'Filepath missing in download request.'}).encode('utf-8'))

            elif msg_type == 'disconnect':
                print(f"[*] Client {client_name} requested disconnect.")
                break
            else:
                print(f"[!] Unknown message type from {client_name}: {msg_type}")
                send_msg(ssl_conn, json.dumps({'type': 'error', 'info': f'Unknown message type: {msg_type}'}).encode('utf-8'))

        except json.JSONDecodeError: print(f"[!] Non-JSON from {client_name}. Closing.") ; break
        except UnicodeDecodeError: print(f"[!] UTF-8 decode error from {client_name}. Closing.") ; break
        except KeyError as e: print(f"[!] Missing key from {client_name}: {e}. Closing.") ; break
        except MemoryError as e: print(f"[!] Memory error processing request from {client_name}: {e}. Closing."); break

    # Cleanup for this client connection
    print(f"[-] Closing connection to {client_name}")
    try:
        ssl_conn.shutdown(socket.SHUT_RDWR)
    except (OSError, ssl.SSLError, socket.error): pass # Ignore errors on shutdown
    finally:
        ssl_conn.close()


# (نفس الدالة run_server من الكود المدمج، مع التأكد من استخدام الدوال المستوردة)
def run_server(host, port, certfile, keyfile, share_dir):
    try:
        os.makedirs(share_dir, exist_ok=True)
        base_share_path_abs = os.path.abspath(share_dir)
        print(f"[*] Sharing directory: {base_share_path_abs}")
        os.listdir(base_share_path_abs) # Test read access
        print("[+] Share directory is accessible.")
    except OSError as e: print(f"[!] Error accessing share dir '{share_dir}': {e}"); return
    except Exception as e: print(f"[!] Unexpected error setting up share dir: {e}"); return

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        print(f"[*] Loading certificate: {certfile}")
        print(f"[*] Loading private key: {keyfile}")
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        print("[+] Certificate and key loaded.")
    except (ssl.SSLError, FileNotFoundError, Exception) as e: print(f"[!] Error loading cert/key: {e}"); return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"[*] Secure Server listening on {host}:{port}")

        while True:
            try:
                conn, addr = server_socket.accept()
                try:
                    ssl_conn = context.wrap_socket(conn, server_side=True)
                    client_thread = threading.Thread(target=handle_client, args=(ssl_conn, addr, base_share_path_abs))
                    client_thread.daemon = True
                    client_thread.start()
                except (ssl.SSLError, Exception) as e: print(f"[!] SSL wrap error {addr}: {e}"); conn.close()
            except socket.error as e: print(f"[!] Accept error: {e}")
            # KeyboardInterrupt is handled by the outer try/except

    except OSError as e: print(f"[!] Server bind/listen error: {e}")
    except KeyboardInterrupt: print("\n[!] Server shutting down.")
    finally: print("[*] Closing server socket."); server_socket.close()

# --- Main Execution Block for Server ---
if __name__ == "__main__":
    openssl_instructions = """
---------------------------------------------------------------------
OpenSSL Setup (Required Before Running Server):
---------------------------------------------------------------------
1. Gen Key: openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
2. Gen Cert: openssl req -new -x509 -key server.key -out server.crt -days 365
   (Ensure 'server.key'/'server.crt' are present or use --key/--cert args)
3. Copy 'server.crt' to clients for verification.
---------------------------------------------------------------------"""

    parser = argparse.ArgumentParser(
        description="Secure Server for File/Message Sharing (SSL/TLS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=openssl_instructions
    )
    parser.add_argument('--cert', default=DEFAULT_CERT_FILE, help="Path to server SSL certificate (PEM)")
    parser.add_argument('--key', default=DEFAULT_KEY_FILE, help="Path to server SSL private key (PEM)")
    parser.add_argument('--share-dir', default=DEFAULT_SHARE_DIR, help="Directory on server to share")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help=f"Port number (default: {DEFAULT_PORT})")

    args = parser.parse_args()

    # Validate cert/key existence before starting
    if not os.path.exists(args.cert):
         print(f"[!] Error: Certificate file not found: {args.cert}")
         exit(1)
    if not os.path.exists(args.key):
         print(f"[!] Error: Private key file not found: {args.key}")
         exit(1)

    run_server('localhost', args.port, args.cert, args.key, args.share_dir)