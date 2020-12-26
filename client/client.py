import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import base64

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
        self.CIPHER = None
        self.MODE = None
        self.DIGEST = None
        self.chosen_suite = None

        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self.symmetric_key = None

        self.num_views = {}

    def negociate(self):
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
            self.CIPHER = suite_params[1]
            if len(suite_params)==4:
                self.MODE = suite_params[2]
                self.DIGEST = suite_params[3]
            else:
                self.DIGEST = suite_params[2]

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

    def get_licence(self, selection):
        # get licence with number of views
        data = requests.get(f'{SERVER_URL}/api/licence')
        if data.status_code == 200:
            self.num_views[selection] = data.json()
            return True
        else:
            return False


    def main(self):

        # Get a list of media files
        req = requests.get(f'{SERVER_URL}/api/list')
        if req.status_code == 200:
            print("Got Server List")

        secure_content = req.json()
        media_list = self.extract_content(secure_content)['media_list']


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

        if (selection not in self.num_views.keys()):
            self.get_licence(selection)
        
        print('LICENCE: ' + str(self.num_views[selection] - 1) + ' views available.')

        if(self.num_views[selection] > 0):
            # adding 1 more view
            self.num_views[selection] -= 1

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
        else:
            print("Licence for this music already expired!")
            print("Getting a new licence from server ...")
            status = self.get_licence(selection)
            if(status):
                print("Got new licence: " + str(self.num_views[selection]) + " views avaliable.")
            else:
                print("Could not get a new licence.")
            


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

        if(self.DIGEST=="SHA256"):
            algorithm=hashes.SHA256()
        elif(self.DIGEST=="SHA384"):
            algorithm=hashes.SHA384()

        key = HKDF(
            algorithm=algorithm,
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(self.shared_key)

        if self.CIPHER == 'AES128':
            self.symmetric_key = key[:16]
        elif self.CIPHER == 'CHACHA20':
            self.symmetric_key = key[:32]

    
    def encryption(self, data):
        cipher = None 
        block_size = 0
        mode = None
        iv = None
        nonce = None
        tag = None
        
        if self.CIPHER == 'AES128':
            iv = os.urandom(16)
            if self.MODE == 'GCM':
                mode = modes.GCM(iv)
            elif self.MODE == 'CBC':
                mode = modes.CBC(iv)
        
        if self.CIPHER == 'AES128':
            block_size = algorithms.AES(self.symmetric_key).block_size
            cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=default_backend)
        
        elif self.CIPHER == 'CHACHA20':
            nonce = os.urandom(16)
            algorithm = algorithms.ChaCha20(self.symmetric_key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
        else:
            raise Exception("Cipher not supported")
        
        
        encryptor = cipher.encryptor()
        
        if self.MODE == 'CBC':
            padding = block_size - len(data) % block_size

            if padding == 0:
                padding = 16

            data += bytes([padding]*padding)
            criptogram = encryptor.update(data)
        elif self.CIPHER == 'CHACHA20':
            criptogram = encryptor.update(data)
        else:
            criptogram = encryptor.update(data)+encryptor.finalize()
            tag = encryptor.tag


        return criptogram,iv,nonce,tag


    def decryption(self, data, iv=None, nonce=None, tag=None):
        cipher = None
        block_size = 0
        mode = None

        if self.CIPHER == 'AES128':
            if self.MODE == 'GCM':
                mode = modes.GCM(iv,tag)
            elif self.MODE == 'CBC':
                mode = modes.CBC(iv)

        if self.CIPHER == 'AES128':
            block_size = algorithms.AES(self.symmetric_key).block_size
            cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=default_backend)
        
        elif self.CIPHER == 'CHACHA20':
            algorithm = algorithms.ChaCha20(self.symmetric_key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
        else:
            raise Exception("Cipher not supported")
            
        decryptor = cipher.decryptor()

        ct = decryptor.update(data)+decryptor.finalize()
        
        if self.MODE =='GCM' or self.CIPHER=='CHACHA20':
            return ct
        return ct[:-ct[-1]]


    def extract_content(self, secure_content):
        iv = base64.b64decode(secure_content['iv'])
        tag = base64.b64decode(secure_content['tag'])
        nonce = base64.b64decode(secure_content['nonce'])

        if iv == '':
            iv = None
        if tag == '':
            tag = None
        if nonce == '':
            nonce = None

        return json.loads(self.decryption(base64.b64decode(secure_content['payload'].encode()),iv,nonce,tag))



client = Client()
client.negociate()
while True:
    client.main()
    time.sleep(1)