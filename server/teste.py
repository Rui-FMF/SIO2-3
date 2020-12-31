import os
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# Salts should be randomly generated
salt = os.urandom(16)
# derive
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = kdf.derive(b"my great password")
# verify
#print(kdf.verify(b"my great password", key))


iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

encryptor = cipher.encryptor()

with open ('catalog_2/1.mp3', 'rb') as f:

    with open ('catalog_2/teste', 'ab') as fw:
        fw.write(binascii.b2a_base64(salt))

    while True:
        data = f.read(8)
        if len(data) < 8:
            encryptor.finalize()
            break
        ct = encryptor.update(data)
        b64 = binascii.b2a_base64(ct)

        with open ('catalog_2/teste', 'ab') as fwap:
            fwap.write(b64)



print("ended encr")
decryptor = cipher.decryptor()

with open ('catalog_2/teste', 'rb') as f:

    with open ('catalog_2/teste_d', 'ab') as fw:
        fw.write(binascii.b2a_base64(f.readline()))

    while True:
        data = f.read(192)
        if len(data) < 192:
            decryptor.finalize()
            break
        ct = decryptor.update(data)
        b64 = binascii.a2b_base64(ct)

        with open ('catalog_2/teste_d', 'ab') as fwap:
            fwap.write(b64)
