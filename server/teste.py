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

with open ('catalog_2/1.mp3', 'rb') as f:
    data = f.read()

    with open ('catalog_2/teste', 'ab') as fw:
        #fw.write(salt)

        padder = padding.PKCS7(128).padder()
        
        padded = padder.update(data) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        #b64 = binascii.b2a_base64(ct)
        fw.write(ct)



print("ended encr")
decryptor = cipher.decryptor()

with open ('catalog_2/teste', 'rb') as f:
    
    with open ('catalog_2/teste_d', 'ab') as fw:

        #fw.write(f.readline())

        data = f.read()

        ct = decryptor.update(data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()

        unpadded = unpadder.update(data) + unpadder.finalize()

        #b64 = binascii.a2b_base64(ct)

        fw.write(ct)
