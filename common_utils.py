
import socket
import struct
import ssl
import json # نحتاجه هنا لإرسال رسائل الخطأ المحتملة في recv_msg

# --- Constants المشتركة ---
DEFAULT_PORT = 65432
BUFFER_SIZE = 4096
DEFAULT_CERT_FILE = "server.crt" # يستخدم كافتراضي للخادم وللعميل (cacert)

# --- Network Helper Functions ---

def send_msg(ssl_sock, data_bytes):
    """يرسل البيانات مع بادئة الطول عبر سوكيت SSL."""
    message_len = len(data_bytes)
    header = struct.pack('!Q', message_len) # 8 bytes for length
    try:
        ssl_sock.sendall(header + data_bytes)
        return True
    except (ssl.SSLError, socket.error, BrokenPipeError) as e:
        # من الأفضل طباعة الخطأ في مكان استدعاء الدالة ليكون السياق أوضح
        # print(f"[!] SSL/Socket error during send: {e}")
        return False # إرجاع فشل للمستدعي للتعامل معه

def recvall(ssl_sock, n):
    """يساعد على استقبال عدد محدد من البايتات (n) من سوكيت SSL."""
    data = bytearray()
    try:
        while len(data) < n:
            packet = ssl_sock.recv(n - len(data))
            if not packet:
                # تم إغلاق الاتصال من الطرف الآخر
                return None
            data.extend(packet)
        return bytes(data)
    except (ConnectionResetError, ssl.SSLError, socket.error, BrokenPipeError):
        # لا نطبع الخطأ هنا، المستدعي يجب أن يعرف أن الاستقبال فشل
        return None # إرجاع None للإشارة إلى خطأ أو إغلاق الاتصال


def recv_msg(ssl_sock):
    """يستقبل بادئة الطول ثم البيانات عبر سوكيت SSL ويفك تشفيرها تلقائياً."""
    # استقبال بادئة الطول (8 بايت)
    raw_msglen = recvall(ssl_sock, 8)
    if not raw_msglen:
        return None # أغلق الطرف الآخر الاتصال أو حدث خطأ

    try:
        msglen = struct.unpack('!Q', raw_msglen)[0]
    except struct.error:
        # فشل فك حزمة الطول (بيانات تالفة)
        return None

    # --- حد أقصى لحجم الرسالة لمنع استهلاك ذاكرة مفرط ---
    MAX_MSG_SIZE = 10 * 1024 * 1024 # 10 MB كسقف للرسائل الوصفية (JSON, etc.)
                                    # قد تحتاج لزيادته إذا كنت ترسل رسائل نصية كبيرة جداً
    if msglen > MAX_MSG_SIZE:
        print(f"[!] Error: Incoming message size ({msglen} bytes) exceeds limit ({MAX_MSG_SIZE} bytes).")
        # لا يمكننا ضمان قراءة الرسالة بأكملها لتفريغ المخزن المؤقت بشكل موثوق دون استهلاك الذاكرة
        # لذلك، من الأفضل أن يقوم المستدعي بإغلاق الاتصال عند تلقي MemoryError أو None هنا.
        # يمكن محاولة إرسال رسالة خطأ، ولكن قد يفشل إذا كان الاتصال سيئًا بالفعل.
        # error_payload = json.dumps({'type': 'error', 'message': 'Message size limit exceeded'}).encode('utf-8')
        # send_msg(ssl_sock, error_payload) # قد يفشل هذا الإرسال
        return MemoryError(f"Message size {msglen} exceeds limit {MAX_MSG_SIZE}") # إرجاع خطأ للمستدعي

    # استقبال البيانات (سيتم فك تشفيرها تلقائياً بواسطة SSL)
    decrypted_payload = recvall(ssl_sock, msglen)
    if not decrypted_payload:
         # حدث خطأ أثناء استقبال الجسم الفعلي للرسالة
         return None

    return decrypted_payload # البيانات المستلمة تكون مفكوكة التشفير جاهزة