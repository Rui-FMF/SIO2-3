import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import base64


from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

class Client():
    def __init__(self):
        self.client_suites = [ 'DH_AES128_CBC_SHA256']
        self.CIPHER = None
        self.MODE = None
        self.DIGEST = None
        self.chosen_suite = None

        self.private_key = None
        self.public_key = None
        self.shared_key = None
        self.symmetric_key = None

        self.num_views = {}

        self.session_id = None

    def negociate(self):
        print("|--------------------------------------|")
        print("|         SECURE MEDIA CLIENT          |")
        print("|--------------------------------------|\n")

        print("Contacting Server")

        req = requests.get(f'{SERVER_URL}/api/contact')

        if req.status_code == 200:
            print("Contacted Server!")

        self.session_id = req.json()

        # Send supported suites to server
        req = requests.get(f'{SERVER_URL}/api/protocols?sessionID={json.dumps(self.session_id)}&suites={json.dumps(self.client_suites)}')
        if req.status_code == 200:
            print("Ended Negotiation")

        
        self.chosen_suite = req.json()


        if self.chosen_suite == None:
            logger.debug(f'No common suite, exiting...')
            self.disconnect()
        else:
            suite_params = self.chosen_suite.split('_')
            self.CIPHER = suite_params[1]
            if len(suite_params)==4:
                self.MODE = suite_params[2]
                self.DIGEST = suite_params[3]
            else:
                self.DIGEST = suite_params[2]


        # Request parameters for DH key generation
        req = requests.get(f'{SERVER_URL}/api/key?sessionID={json.dumps(self.session_id)}')
        if req.status_code == 200:
            print("Got parameters for DH keys")

        dh_params = req.json()

        # Generate shared key
        self.DH_make_keys(dh_params[0],dh_params[1],dh_params[2])

        # send to the server the client public key

        req = requests.post(f'{SERVER_URL}/api/key?sessionID={json.dumps(self.session_id)}&p={json.dumps(dh_params[0])}&g={json.dumps(dh_params[1])}&pubkey={json.dumps(self.public_key)}')
        if req.status_code == 200:
            print("Exchanged keys")


    def main(self):

        # Get a list of media files
        req = requests.get(f'{SERVER_URL}/api/list?sessionID={json.dumps(self.session_id)}')
        if req.status_code == 200:
            print("Got Server List")

        secure_content = req.json()
        media_list = self.extract_content(secure_content)['media_list']


        # Present a simple selection menu    
        idx = 0
        print("MEDIA CATALOG\n")
        for item in media_list:
            print(f'{idx} - {media_list[idx]["name"]}')
            idx+=1
        print("----")

        while True:
            selection = input("Select a media file number (q to quit): ")
            if selection.strip() == 'q':
                self.disconnect()

            if not selection.isdigit():
                continue

            selection = int(selection)
            if 0 <= selection < len(media_list):
                break


        # Example: Download first file
        media_item = media_list[selection]

        req = requests.get(f'{SERVER_URL}/api/license?sessionID={json.dumps(self.session_id)}&id={media_item["id"]}')
        if req.status_code == 402:
            if self.renew_license(media_item["id"]):
                views = 4
            else:
                return
        else:
            views = self.extract_content(req.json())


        print(f"Playing {media_item['name']}")

        # Detect if we are running on Windows or Linux
        # You need to have ffplay or ffplay.exe in the current folder
        # In alternative, provide the full path to the executable
        if os.name == 'nt':
            proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
        else:
            proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

        duration = media_item['duration']
        initTime = time.time()

        # Get data from server and send it to the ffplay stdin through a pipe
        for chunk in range(media_item['chunks']):

            req = requests.get(f'{SERVER_URL}/api/download?sessionID={json.dumps(self.session_id)}&id={media_item["id"]}&chunk={chunk}')

            chunk = self.extract_content(req.json())

            data = binascii.a2b_base64(chunk['data'].encode('latin'))
            try:
                proc.stdin.write(data)
            except:
                break
        
        
        print("You now have "+str(views)+" remaining views on this media item")

        while (time.time()-initTime) < duration+5:
            time.sleep(5)                           #TODO melhorar/arranjar isto
        proc.terminate()

            


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
            cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=default_backend())
        
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
            cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=default_backend())
        
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
        mac = base64.b64decode(secure_content['MAC'])
        payload = base64.b64decode(secure_content['payload'])

        if self.check_MAC(mac, payload):
            print("Message passed Integrity check")
        else:
            print("Message failed Integrity check, Shutting Down...")
            self.disconnect()

        if iv == '':
            iv = None
        if tag == '':
            tag = None
        if nonce == '':
            nonce = None

        return json.loads(self.decryption(payload,iv,nonce,tag))

    def secure(self, content):

        secure_content = {'payload': None}
        payload = json.dumps(content).encode()

        criptogram,iv,nonce,tag = self.encryption(payload)
        secure_content['payload'] = base64.b64encode(criptogram).decode()

        mac = self.make_MAC(criptogram)
        secure_content['MAC'] = base64.b64encode(mac).decode()

        if iv is None:
            secure_content['iv'] = ''
        else:
            secure_content['iv'] = base64.b64encode(iv).decode()

        if tag is None:
            secure_content['tag'] = ''
        else:
            secure_content['tag'] = base64.b64encode(tag).decode()

        if nonce is None:
            secure_content['nonce'] = ''
        else:
            secure_content['nonce'] = base64.b64encode(nonce).decode()

        return secure_content

    def check_MAC(self, server_mac, data):
        client_mac = self.make_MAC(data)

        if client_mac == server_mac:
            return True
        else:
            return False

    def make_MAC(self, data):

        if(self.DIGEST=="SHA256"):
            h = hmac.HMAC(self.symmetric_key, hashes.SHA256(), backend=default_backend())
        elif(self.DIGEST=="SHA384"):
            h = hmac.HMAC(self.symmetric_key, hashes.SHA384(), backend=default_backend())

        h.update(data) 

        return binascii.hexlify(h.finalize())

    def disconnect(self):
        req = requests.post(f'{SERVER_URL}/api/close?sessionID={json.dumps(self.session_id)}')
        sys.exit(0)

    def renew_license(self, media_item):
        while True:
            print("License for Media Item "+str(media_item)+" has expired, would you like to pay 5$ to renew it for 5 more views?")
            selection = input("(Y)es/(N)o: ")
            if selection.strip() == 'Y':
                req = requests.post(f'{SERVER_URL}/api/renew', data={'sessionID': self.session_id, 'id': media_item})
                return True
            elif selection.strip() == 'N':
                return False
            else:
                continue



client = Client()
client.negociate()
while True:
    client.main()
    time.sleep(1)