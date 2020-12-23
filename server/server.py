#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math

# DH
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# AES
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

class MediaServer(resource.Resource):
    isLeaf = True

    def __init__(self):
        self.SERVER_SUITES = ['DH_CHACHA20_SHA384', 'DH_CHACHA20_SHA256', 'DH_AES128_GCM_SHA384', 'DH_AES128_GCM_SHA256', 'DH_AES128_CBC_SHA384', 'DH_AES128_CBC_SHA256']

        self.CIPHER = None
        self.MODE = None         #TODO o server vai ter de suportar mais q 1 client e as suites podem ter os compenentes separados
        self.DIGEST = None
        self.SUITE = None

        self.private_key = None
        self.public_key = None
        self.shared_key = None

        self.symmetric_key = None

    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')

    #Negotiate cipher suites and choose best protocol
    def do_get_protocols(self, request):
        logger.debug(f'Negotiate: args: {request.args}')

        suite_list = request.args.get(b'suites', [None])[0]
        logger.debug(f'Negotiate: suites: {suite_list}')

        suite_list.decode('latin')
        suite_list = json.loads(suite_list)

        chosen_suite = None
        for s in self.SERVER_SUITES:
            if s in suite_list:
                chosen_suite = s
                params = s.split('_')
                self.CIPHER = params[1]
                if len(params)==4:
                    self.MODE = params[2]
                    self.DIGEST = params[3]
                else:
                    self.DIGEST = params[2]
                break

        self.SUITE=chosen_suite
        logger.debug(f'Chosen suite: {chosen_suite}')

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(chosen_suite, indent=4).encode('latin')

    def do_dh_keys(self, request):

        parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

        self.private_key = parameters.generate_private_key()

        peer_public_key = self.private_key.public_key()
        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g

        self.public_key = peer_public_key.public_numbers().y

        logger.debug(f'server public key:: {self.public_key}')

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps((p,g,self.public_key), indent=4).encode('latin')

    def gen_shared_key(self, request):
        p = int(request.args.get(b'p', [None])[0])
        g = int(request.args.get(b'g', [None])[0])
        client_key = int(request.args.get(b'pubkey', [None])[0])

        pnum = dh.DHParameterNumbers(p, g)
        self.shared_key = self.private_key.exchange(dh.DHPublicNumbers(client_key,pnum).public_key())

        # With the shared key we can know derive it
        self.gen_symmetric_key()

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(True, indent=4).encode('latin')

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

    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/key':
                return self.do_dh_keys(request)

            #elif request.uri == 'api/auth':

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
    
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        
        try:
            if request.path == b'/api/key':
                return self.gen_shared_key(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/key '

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

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


print("Server started")
print("URL is: http://IP:8080")



s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()