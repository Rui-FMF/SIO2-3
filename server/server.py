#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
import base64
import requests
from random import randint

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import padding as pad

# open server private key
with open("private_key.pem", "rb") as f:
    SERVER_PK  = serialization.load_pem_private_key(f.read(), password=None)

# open server certificate
SERVER_CERT = open("cert.pem", 'rb').read().decode()

# open content private key
with open("../content/content_key.pem", 'rb') as f:
    CONTENT_PK = serialization.load_pem_private_key(f.read(), password=None)

# open content certificate
CONTENT_CERT = open("../content/content_certificate.pem", 'rb').read().decode()

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
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce',
                'file_size': 3407202
            },

            'rick_astley': 
            {
                'name': 'Never Gonna Give You Up - Rick Astley',
                'album': 'Whenever You Need Somebody',
                'description': 'Rick Rolled',
                'duration': 16,
                'file_name': 'rick_astley',
                'file_size': 272092
            }
        }


CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

class MediaServer(resource.Resource):
    isLeaf = True

    def __init__(self):
        # server's supported suites
        self.SERVER_SUITES = ['DH_CHACHA20_SHA384', 'DH_CHACHA20_SHA256', 'DH_AES128_GCM_SHA384', 'DH_AES128_GCM_SHA256', 'DH_AES128_CBC_SHA384', 'DH_AES128_CBC_SHA256']
        # sessions
        self.open_sessions = {} # {session_id:{session_info}}

    # Send the list of media files to clients
    def do_list(self, request):
        # get session
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]


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

        content = {'media_list': media_list}
        secure_content = self.secure(content, session)

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(secure_content, indent=4).encode('latin')

    #Negotiate cipher suites and choose best protocol
    def do_get_protocols(self, request):
        logger.debug(f'Negotiate: args: {request.args}')

        # client's supported suites
        suite_list = request.args.get(b'suites', [None])[0]
        logger.debug(f'Negotiate: suites: {suite_list}')

        suite_list.decode('latin')
        suite_list = json.loads(suite_list)

        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]

        # choose a suite
        chosen_suite = None
        for s in self.SERVER_SUITES:
            if s in suite_list:
                chosen_suite = s
                params = s.split('_')
                session['cipher'] = params[1]
                if len(params)==4:
                    session['mode'] = params[2]
                    session['digest'] = params[3]
                else:
                    session['digest'] = params[2]
                    session['mode'] = ''
                break

        session['suite'] = chosen_suite
        logger.debug(f'Chosen suite: {chosen_suite}')

        # generate DH parameters
        dh_params = self.do_dh_keys(request)

        # server signature
        signature = self.sign(session['suite'], str(dh_params[2]).encode() + str(dh_params[0]).encode() + str(dh_params[1]).encode())

        # send server certificate and signature to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'chosen_suite': chosen_suite, 'certificate': SERVER_CERT, 'signature': signature.decode('latin'), 'y': dh_params[2], 'p': dh_params[0], 'g': dh_params[1]}).encode('latin')

    def do_dh_keys(self, request):
        # session
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]

        # generate parameters
        parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

        # save them
        session['private_key'] = parameters.generate_private_key()

        peer_public_key = session['private_key'].public_key()
        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g

        session['public_key'] = peer_public_key.public_numbers().y

        session['p'] = p
        session['g'] = g

        logger.debug(f'server public key: {session["public_key"]}')

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps((p,g,session['public_key']), indent=4).encode('latin')

    def gen_shared_key(self, request):
        # session
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]

        client_key = int(request.args.get(b'pubkey', [None])[0])

        pnum = dh.DHParameterNumbers(session['p'], session['g'])
        session['shared_key'] = session['private_key'].exchange(dh.DHPublicNumbers(client_key,pnum).public_key())

        # With the shared key we can now derive it
        self.gen_symmetric_key(session)

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(True, indent=4).encode('latin')

    def check_client(self, request):
        # get session
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]

        # decrypt content
        secure_data = request.args
        data = self.extract_content(secure_data)

        # client certificate
        cert = x509.load_pem_x509_certificate(data['certificate'].encode('latin'))

        # client public key
        CLIENT_PUBLIC_KEY = cert.public_key()

        # check client signature
        self.check_sign(data['signature'].encode('latin'), session['suite'], CLIENT_PUBLIC_KEY, str(data['pubkey']).encode())
        logger.debug(f'Client certificate validated successfully.')

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(True, indent=4).encode('latin')



    def gen_symmetric_key(self, session):

        if(session['digest']=="SHA256"):
            algorithm = hashes.SHA256()
        elif(session['digest']=="SHA384"):
            algorithm = hashes.SHA384()

        key = HKDF(
            algorithm=algorithm,
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(session['shared_key'])

        if session['cipher'] == 'AES128':
            session['symmetric_key'] = key[:16]
        elif session['cipher'] == 'CHACHA20':
            session['symmetric_key'] = key[:32]

    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')

        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(self.secure({'error': 'invalid media id'}, session)).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(self.secure({'error': 'media file not found'}, session)).encode('latin')
        
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
            return json.dumps(self.secure({'error': 'invalid chunk id'}, session)).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            # read key
            key = f.read(16)
            # read iv
            iv = f.read(16)
            # cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            # decrypt file
            decryptor = cipher.decryptor()
            d = f.read()
            ct = decryptor.update(d) + decryptor.finalize()
            # unpad
            unpadder = pad.PKCS7(128).unpadder()
            ct1 = unpadder.update(ct) + unpadder.finalize()

            # chunk
            data = ct1[offset : offset + CHUNK_SIZE]

            session['download_count']+=1

            if session['download_count']==500:
                logger.debug(f'Reached 500 chunk downloads, requesting new key exchange')
                needs_rotation = True
                session['download_count'] = 0
            else:
                needs_rotation = False

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(self.secure(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip(),
                        'needs_rotation': needs_rotation
                    }, session),indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(self.secure({'error': 'unknown'}, session), indent=4).encode('latin')
    
    def check_license(self, request):
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]
        
        media_id = request.args.get(b'id', [None])[0].decode('latin')
        # In case of first chunk:
        # Check if user has a license for this media, if it's the first time, then a 5 views license will be given
        if media_id not in session['licenses']:
            session['licenses'][media_id] = 4
        else:
            if session['licenses'][media_id] < 1:
                request.setResponseCode(402)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(self.secure({'error': 'license for this media expired'}, session)).encode('latin')
            else:
                session['licenses'][media_id]-=1


        request.setResponseCode(200)
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(self.secure(session['licenses'][media_id], session), indent=4).encode('latin')

    def renew_license(self, request):
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]

        secure_data = request.args
        data = self.extract_content(secure_data)

        media_id = data['id']

        session['licenses'][media_id] = 4

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(True, indent=4).encode('latin')

    
    def make_session(self, request):

        session_id = len(self.open_sessions)

        while session_id in self.open_sessions:
            session_id+=1

        self.open_sessions[session_id] = {}

        self.open_sessions[session_id]['licenses'] = {}
        self.open_sessions[session_id]['download_count'] = 0
        
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(session_id, indent=4).encode('latin')

    def close_session(self, request):
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        self.open_sessions.pop(session_id, None)

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(True, indent=4).encode('latin')

    def auth_content(self, request):
        # session
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]

        # signature of the content certificate
        signature = self.sign_content(session['suite'], str(session['public_key']).encode() + str(session['p']).encode() + str(session['g']).encode())

        # send content certificate and signature to client
        content = {'certificate': CONTENT_CERT, 'signature': signature.decode('latin'), 'y': session['public_key'], 'p': session['p'], 'g': session['g']}
        secure_content = self.secure(content, session)
        # send it to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(secure_content).encode('latin')


    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/key':
                # session
                session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
                session = self.open_sessions[session_id]
                # return dh params
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps((session['p'], session['g'], session['public_key']), indent=4).encode('latin')

            elif request.path == b'/api/contact':
                return self.make_session(request)

            elif request.path == b'/api/list':
                return self.do_list(request)

            elif request.path == b'/api/download':
                return self.do_download(request)

            elif request.path == b'/api/license':
                return self.check_license(request)
            
            elif request.path == b'/api/content':
                return self.auth_content(request)

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
            
            elif request.path == b'/api/cert':
                return self.check_client(request)

            elif request.path == b'/api/close':
                return self.close_session(request)
            
            elif request.path == b'/api/user':
                return self.check_user(request)

            elif request.path == b'/api/renew':
                return self.renew_license(request)

            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/key /api/close /api/renew'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    def encryption(self, data, session):
        cipher = None 
        block_size = 0
        mode = None
        iv = None
        nonce = None
        tag = None
        
        if session['cipher'] == 'AES128':
            iv = os.urandom(16)
            if session['mode'] == 'GCM':
                mode = modes.GCM(iv)
            elif session['mode'] == 'CBC':
                mode = modes.CBC(iv)
        
        if session['cipher'] == 'AES128':
            block_size = algorithms.AES(session['symmetric_key']).block_size
            cipher = Cipher(algorithms.AES(session['symmetric_key']), mode, backend=default_backend())
        
        elif session['cipher'] == 'CHACHA20':
            nonce = os.urandom(16)
            algorithm = algorithms.ChaCha20(session['symmetric_key'], nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
        else:
            raise Exception("Cipher not supported")
        
        
        encryptor = cipher.encryptor()
        
        if session['mode'] == 'CBC':
            padding = block_size - len(data) % block_size

            if padding == 0:
                padding = 16

            data += bytes([padding]*padding)
            criptogram = encryptor.update(data)
        elif session['cipher'] == 'CHACHA20':
            criptogram = encryptor.update(data)
        else:
            criptogram = encryptor.update(data)+encryptor.finalize()
            tag = encryptor.tag


        return criptogram,iv,nonce,tag


    def decryption(self, data, session, iv=None, nonce=None, tag=None):
        cipher = None
        block_size = 0
        mode = None

        if session['cipher'] == 'AES128':
            if session['mode'] == 'GCM':
                mode = modes.GCM(iv,tag)
            elif session['mode'] == 'CBC':
                mode = modes.CBC(iv)

        if session['cipher'] == 'AES128':
            block_size = algorithms.AES(session['symmetric_key']).block_size
            cipher = Cipher(algorithms.AES(session['symmetric_key']), mode, backend=default_backend())
        
        elif session['cipher'] == 'CHACHA20':
            algorithm = algorithms.ChaCha20(session['symmetric_key'], nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
        else:
            raise Exception("Cipher not supported")
            
        decryptor = cipher.decryptor()

        ct = decryptor.update(data)+decryptor.finalize()
        
        if session['mode'] =='GCM' or session['cipher']=='CHACHA20':
            return ct
        return ct[:-ct[-1]]


    def secure(self, content, session):

        secure_content = {'payload': None}
        payload = json.dumps(content).encode()

        criptogram,iv,nonce,tag = self.encryption(payload, session)
        secure_content['payload'] = base64.b64encode(criptogram).decode()

        mac = self.make_MAC(criptogram, session)
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


    def extract_content(self, secure_content):
        iv = base64.b64decode(secure_content[b'iv'][0])
        tag = base64.b64decode(secure_content[b'tag'][0])
        nonce = base64.b64decode(secure_content[b'nonce'][0])
        mac = base64.b64decode(secure_content[b'MAC'][0])
        payload = base64.b64decode(secure_content[b'payload'][0])
        session_id = json.loads(secure_content[b'sessionID'][0].decode('latin'))
        session = self.open_sessions[session_id]

        if self.check_MAC(mac, payload, session):
            logger.debug(f"Message passed Integrity check")
        else:
            logger.debug(f"Message failed Integrity check, Shutting Down...")
            self.disconnect()

        if iv == '':
            iv = None
        if tag == '':
            tag = None
        if nonce == '':
            nonce = None

        return json.loads(self.decryption(payload,session,iv,nonce,tag))

    def make_MAC(self, data, session):

        if(session['digest']=="SHA256"):
            h = hmac.HMAC(session['symmetric_key'], hashes.SHA256(), backend=default_backend())
        elif(session['digest']=="SHA384"):
            h = hmac.HMAC(session['symmetric_key'], hashes.SHA384(), backend=default_backend())

        h.update(data) 
  
        return binascii.hexlify(h.finalize())

    def check_MAC(self, client_mac, data, session):
        server_mac = self.make_MAC(data, session)

        if client_mac == server_mac:
            return True
        else:
            return False

    def sign(self, suite, data):
        # if SHA384 is used
        if "SHA384" in suite:
            signature = SERVER_PK.sign(
                data,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA384()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA384()
            )

        # if SHA256 is used
        elif "SHA256" in suite:
            signature = SERVER_PK.sign(
                data,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA256()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        return signature
    
    def check_sign(self, signature, suite, pubkey, data):
        # if SHA384 is used
        if "SHA384" in suite:
            pubkey.verify(
                signature,
                data,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA384()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA384()
            )

        # if SHA256 is used
        elif "SHA256" in suite:
            pubkey.verify(
                signature,
                data,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA256()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

    def sign_content(self, suite, data):
        # if SHA384 is used
        if "SHA384" in suite:
            signature = CONTENT_PK.sign(
                data,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA384()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA384()
            )
        
        # if SHA256 is used
        elif "SHA256" in suite:
            signature = CONTENT_PK.sign(
                data,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA256()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        
        return signature
    
    def check_user(self, request):
        # decrypt data
        secure_data = request.args
        data = self.extract_content(secure_data)

        # cc info
        cc_list = json.loads(data['data'])

        # session info
        session_id = json.loads(request.args.get(b'sessionID', [None])[0].decode('latin'))
        session = self.open_sessions[session_id]

        # cc certificate
        citizen_cert = x509.load_der_x509_certificate(cc_list['certificate'][0].encode('latin'))

        # user id
        user_id = citizen_cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
        
        try:
            # verifying cc signature
            citizen_cert.public_key().verify(
                cc_list['signature'].encode('latin'),
                user_id.encode(),
                padding.PKCS1v15(),
                hashes.SHA1()
            )

            # check all cc info
            if self.check_chain(cc_list['certificate']):
                session['user_id'] = user_id
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(self.secure({'user_id': user_id, 'status': 0}, session)).encode('latin')

            # something is invalid
            else:
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(self.secure({'user_id': user_id, 'status': 1}, session)).encode('latin')

        except:
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(self.secure({'user_id': user_id, 'status': 1}, session)).encode('latin')

    def check_chain(self, cert_info):
        
        # check crl delta
        if not self.check_crl(cert_info):
            return False

        # certificate
        cert = x509.load_der_x509_certificate(cert_info[0].encode('latin'))

        # issuer
        issuer = x509.load_der_x509_certificate(cert_info[1].encode('latin'))
        issuer_pubkey = issuer.public_key()

        try:
            issuer_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except:
            logger.debug(f'INVALID ISSUER.')
            return False

        return True

    def check_crl(self, cert_info):
        
        # certificate
        certificate = cert_info[0].encode('latin')
        cert = x509.load_der_x509_certificate(certificate)

        # first condition
        req = requests.get(cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value[0].full_name[0].value)
        cert_crl = x509.load_der_x509_crl(req.content)

        # second condition
        req2 = requests.get(cert.extensions.get_extension_for_oid(ExtensionOID.FRESHEST_CRL).value[0].full_name[0].value)
        cert_crl2 = x509.load_der_x509_crl(req2.content)

        # if they are not revoked
        if (cert_crl2.get_revoked_certificate_by_serial_number(cert.serial_number) is None) and (cert_crl.get_revoked_certificate_by_serial_number(cert.serial_number) is  None):
            return True

        return False


        


print("Server started")
print("URL is: http://IP:8080")



s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()