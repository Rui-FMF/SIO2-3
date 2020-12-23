import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys

# DH
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.backends import default_backend

# AES / CHACHA20
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

class Client():
    def __init__(self):
        self.client_suites = ['DH_AES128_CBC_SHA384', 'DH_CHACHA20_SHA256', 'DH_AES128_GCM_SHA256']
        self.cipher = None
        self.mode = None
        self.digest = None
        self.chosen_suite = None

        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self.symmetric_key = None

    def main(self):
        print("|--------------------------------------|")
        print("|         SECURE MEDIA CLIENT          |")
        print("|--------------------------------------|\n")

        print("Contacting Server")

        # Send supported suites to server
        req = requests.get(f'{SERVER_URL}/api/protocols?suites={json.dumps(self.client_suites)}')
        if req.status_code == 200:
            print("Ended Negotiation")

        
        self.chosen_suite = req.json()


        if self.chosen_suite == None:
            logger.debug(f'No common suite, exiting...')
            exit(0)
        else:
            suite_params = self.chosen_suite.split('_')
            self.cipher = suite_params[1]
            if len(suite_params)==4:
                self.mode = suite_params[2]
                self.digest = suite_params[3]
            else:
                self.digest = suite_params[2]

        # Request parameters for DH key generation
        req = requests.get(f'{SERVER_URL}/api/key')
        if req.status_code == 200:
            print("Got parameters for DH keys")

        dh_params = req.json()

        # Generate shared key
        self.DH_make_keys(dh_params[0],dh_params[1],dh_params[2])

        # send to the server the client public key

        req = requests.post(f'{SERVER_URL}/api/key?p={json.dumps(dh_params[0])}&g={json.dumps(dh_params[1])}&pubkey={json.dumps(self.public_key)}')
        if req.status_code == 200:
            print("Exchanged keys")


        # Get a list of media files
        req = requests.get(f'{SERVER_URL}/api/list')
        if req.status_code == 200:
            print("Got Server List")

        media_list = req.json()


        # Present a simple selection menu    
        idx = 0
        print("MEDIA CATALOG\n")
        for item in media_list:
            print(f'{idx} - {media_list[idx]["name"]}')
        print("----")

        while True:
            selection = input("Select a media file number (q to quit): ")
            if selection.strip() == 'q':
                sys.exit(0)

            if not selection.isdigit():
                continue

            selection = int(selection)
            if 0 <= selection < len(media_list):
                break

        # Example: Download first file
        media_item = media_list[selection]
        print(f"Playing {media_item['name']}")

        # Detect if we are running on Windows or Linux
        # You need to have ffplay or ffplay.exe in the current folder
        # In alternative, provide the full path to the executable
        if os.name == 'nt':
            proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
        else:
            proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

        # Get data from server and send it to the ffplay stdin through a pipe
        for chunk in range(media_item['chunks'] + 1):
            req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
            chunk = req.json()
        
            # TODO: Process chunk

            data = binascii.a2b_base64(chunk['data'].encode('latin'))
            try:
                proc.stdin.write(data)
            except:
                break

    def DH_make_keys(self,p,g,server_key):
        pnum = dh.DHParameterNumbers(p, g)
        parameters = pnum.parameters(default_backend())
        self.private_key = parameters.generate_private_key()

        peer_public_key = self.private_key.public_key()
        self.public_key = peer_public_key.public_numbers().y

        self.shared_key = self.private_key.exchange(dh.DHPublicNumbers(server_key,pnum).public_key())

        # With the shared key we can know derive it
        self.gen_symmetric_key()

        return True

    def gen_symmetric_key(self):

        if(self.digest=="SHA256"):
            algorithm=hashes.SHA256()
        elif(self.digest=="SHA384"):
            algorithm=hashes.SHA384()

        key = HKDF(
            algorithm=algorithm,
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(self.shared_key)

        if self.cipher == 'AES128':
            self.symmetric_key = key[:16]
        elif self.cipher == 'CHACHA20':
            self.symmetric_key = key[:32]

def AES128_CBC_encrypt(self, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(key) + encryptor.finalize()

        return ct

def CHACHA20_encrypt(self, key):
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ct = encryptor.update(key)

    return ct


client = Client()
while True:
    client.main()
    time.sleep(1)