import binascii
import datetime
from base64 import b64encode, b64decode

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class ChatHeader:
    def __init__(self, date_time, version, message_type, body, encryption):
        self.timestamp = self.set_timestamp(date_time)
        self.version = version
        self.message_type = message_type
        self.crc = self.set_crc(body)
        self.encryption = encryption
        self.body_length = len(body.body)

    def set_timestamp(self, date_time):
        return int(datetime.datetime.timestamp(date_time))

    def datetime_from_timestamp(self):
        return datetime.datetime.fromtimestamp(self.timestamp)

    def set_crc(self, body):
        return f"{binascii.crc32(body.body.encode('utf-8')):08X}"

    def encrypt(self, body):
        data_as_bytes = body.body.encode("utf-8")
        recipient_key = RSA.import_key(open("Server_pub.pem").read())

        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher = AES.new(session_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data_as_bytes, AES.block_size))

        body.session_key = b64encode(enc_session_key).decode('utf-8')
        body.iv = b64encode(cipher.iv).decode('utf-8')
        body.body = b64encode(ct_bytes).decode('utf-8')

    def room_recrypt(self, body, client_pub_key):
        private_key = RSA.import_key(open("Server_priv.pem").read())
        # Decrypt message session key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        enc_session_key = b64decode(body.session_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Re-encrypt the session key using the clients public key
        cipher_rsa = PKCS1_OAEP.new(client_pub_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        body.session_key = b64encode(enc_session_key).decode('utf-8')

    def decrypt(self, body, client_priv):
        cipher_rsa = PKCS1_OAEP.new(client_priv)
        enc_session_key = b64decode(body.session_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        iv = b64decode(body.iv)
        ct = b64decode(body.body)
        cipher = AES.new(session_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')


class ChatBody:
    def __init__(self, body=None):
        self.iv = None
        self.session_key = None
        self.body = body

    def copy(self):
        body = ChatBody()
        body.iv = self.iv
        body.session_key = self.session_key
        body.body = self.body
        return body


class ChatMessageProtocol:
    def __init__(self, header, body):
        self.header = header
        self.body = body


# Sender client
cb = ChatBody("hej.")

ch = ChatHeader(datetime.datetime.now(), 1.0, 2, cb, False)
#ch.encrypt(cb)
chat_package = ChatMessageProtocol(ch, cb)


# Servern
b_pub = RSA.import_key(open("B_pub.pem").read())
c_pub = RSA.import_key(open("C_pub.pem").read())

b_cb = chat_package.body.copy()
c_cb = chat_package.body.copy()

if chat_package.header.encryption:
    ch.room_recrypt(b_cb, b_pub)
    ch.room_recrypt(c_cb, c_pub)

b_package = ChatMessageProtocol(chat_package.header, b_cb)
c_package = ChatMessageProtocol(chat_package.header, c_cb)

# Receiver client B
header = b_package.header
body = b_package.body

if header.version == 1.0:
    if header.encryption:
        b_priv = RSA.import_key(open("B_priv.pem").read())
        msg = ch.decrypt(body, b_priv)
        print("Client B:", msg)
    else:
        print("Client B:", body.body)

# Receiver client C
header = c_package.header
body = c_package.body
if header.version == 1.0:
    if header.encryption:
        c_priv = RSA.import_key(open("C_priv.pem").read())
        msg = ch.decrypt(body, c_priv)
        print("Client C:", msg)
    else:
        print("Client C:", body.body)