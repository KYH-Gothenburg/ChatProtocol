import binascii
import datetime
from base64 import b64encode, b64decode

from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class ChatHeader:
    def __init__(self, date_time, version, message_type, encryption, body=None, crc=None):
        self.timestamp = self.set_timestamp(date_time)
        self.version = version
        self.message_type = message_type
        if body:
            self.crc = self.set_crc(body)
        elif crc:
            self.crc = crc
        else:
            raise ValueError("Must pass either body or crc")
        self.encryption = encryption


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

    def __bytes__(self):
        return repr(self).encode('utf-8')

    def __repr__(self):
        return f"{self.timestamp}:<>:{self.version}:<>:{self.message_type}:<>:{self.crc}:<>:{self.encryption}:<>:"

class ChatBody:
    def __init__(self, body=None, iv=None, session_key=None):
        self.iv = iv
        self.session_key = session_key
        self.body = body

    def copy(self):
        body = ChatBody()
        body.iv = self.iv
        body.session_key = self.session_key
        body.body = self.body
        return body

    def __repr__(self):
        return f"{self.iv}:<>:{self.session_key}:<>:{self.body}"

    def __bytes__(self):
        return repr(self).encode('utf-8')


class ChatMessageProtocol:
    def __init__(self, header: ChatHeader=None, body: ChatBody=None):
        self.header = header
        self.body = body

    def __bytes__(self):
        header = bytes(self.header)
        body = bytes(self.body)

        return header + body

    @staticmethod
    def from_bytes(byte_data: bytes):
        chat_message_object = ChatMessageProtocol()
        in_msg = byte_data.decode('utf-8')
        data = in_msg.split(':<>:')
        date_time = datetime.datetime.fromtimestamp(int(data[0]))
        chat_header = ChatHeader(date_time, data[1], int(data[2]), bool(data[4]), crc=data[3])
        chat_message_object.header = chat_header
        chat_body = ChatBody(data[5], data[7], data[6])
        chat_message_object.body = chat_body
        return chat_message_object



# Sender client
cb = ChatBody("hej.")

ch = ChatHeader(datetime.datetime.now(), '1.0', 2, True, body=cb)
if ch.encryption:
    ch.encrypt(cb)
chat_package = ChatMessageProtocol(ch, cb)

cp_as_bytes = bytes(chat_package)
# Send cp_as_bytes


# Servern
# Receive cp_as_bytes
b_pub = RSA.import_key(open("B_pub.pem").read())
c_pub = RSA.import_key(open("C_pub.pem").read())

new_chat_package = ChatMessageProtocol.from_bytes(cp_as_bytes)

# Copy for each receiving client
b_cb = new_chat_package.body.copy()
c_cb = new_chat_package.body.copy()

# Re-encrypt session key for each client
if chat_package.header.encryption:
    ch.room_recrypt(b_cb, b_pub)
    ch.room_recrypt(c_cb, c_pub)

# Create packge for each client
b_package = ChatMessageProtocol(chat_package.header, b_cb)
c_package = ChatMessageProtocol(chat_package.header, c_cb)

# Send bytes to each client
b_bytes = bytes(b_package)
c_bytes = bytes(c_package)

# Receiver client B
# Receive b_bytes
new_b_package = ChatMessageProtocol.from_bytes(b_bytes)
header = new_b_package.header
body = new_b_package.body

if header.version == '1.0':
    if header.encryption:
        b_priv = RSA.import_key(open("B_priv.pem").read())
        msg = ch.decrypt(body, b_priv)
        print("Client B:", msg)
    else:
        print("Client B:", body.body)

# Receiver client C
# Receive c_bytes
new_c_package = ChatMessageProtocol.from_bytes(c_bytes)
header = new_c_package.header
body = new_c_package.body
if header.version == '1.0':
    if header.encryption:
        c_priv = RSA.import_key(open("C_priv.pem").read())
        msg = ch.decrypt(body, c_priv)
        print("Client C:", msg)
    else:
        print("Client C:", body.body)