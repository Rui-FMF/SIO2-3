import os
import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
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

with open ('catalog_2/2.mp3', 'rb') as f:
    data = f.read()

    with open ('catalog_2/teste', 'ab') as fw:
        fw.write(key)
        fw.write(iv)

        padder = padding.PKCS7(128).padder()
        
        padded = padder.update(data) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        #b64 = binascii.b2a_base64(ct)
        fw.write(ct)



print("ended encr")


with open ('catalog_2/teste', 'rb') as f:
    decryptor = cipher.decryptor()
    x = f.read(16)
    y = f.read(16)
    with open ('catalog_2/teste_d.mp3', 'ab') as fw:
        
        data = f.read()
        ct = decryptor.update(data) + decryptor.finalize()
        fw.write(ct)
