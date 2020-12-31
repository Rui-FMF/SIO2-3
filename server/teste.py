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
key = key[16:]

iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

encryptor = cipher.encryptor()

with open ('catalog/rick_astley.mp3', 'rb') as f:
    data1 = f.read()

    with open ('catalog/rick_astley', 'ab') as fw:
        fw.write(key)
        fw.write(iv)

        padder = padding.PKCS7(128).padder()
        
        padded = padder.update(data1) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        fw.write(ct)

encryptor = cipher.encryptor()

with open ('catalog/898a08080d1840793122b7e118b27a95d117ebce.mp3', 'rb') as f:
    data1 = f.read()

    with open ('catalog/898a08080d1840793122b7e118b27a95d117ebce', 'ab') as fw:
        fw.write(key)
        fw.write(iv)

        padder = padding.PKCS7(128).padder()
        
        padded = padder.update(data1) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        fw.write(ct)
