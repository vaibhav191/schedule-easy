# Crypto should be a service
# To Do in production: Leverage AWS KMS to fetch keys
# Fetches keys from json files
# Caller should know which key they want to fetch
# 1. Asymm encryption for Google Oauth Credentials
# 2. Asymm encryption for jwt token
# 3. Asymm encryption for jwt refresh token
# 4. Symm encryption with real time key generation for redis cache data (stores keys themselves 
# so many fetches arent required)
# https://pyjwt.readthedocs.io/en/stable/algorithms.html#asymmetric-public-key-algorithms

'''
private_key = ec.generate_private_key(ec.SECP384R1())
pem = private_key.private_bytes(encoding = Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=BestAvailableEncryption(b'password'))

pem_pub = public_key.public_bytes(encoding = Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

encoded = jwt.encode({"Some":"data"}, serialization.load_pem_private_key(pem,password=passphrase,backend=default_backend()), algorithm="ES256K")
jwt.decode(encoded,pem_pub, "ES256K", options={"verify_signature":True})
'''
'''
To Do:
- Before responding encode with base64
- Decode using base64 (only accepts bytes)
    - whenever sending data to the service, encode with base64 to get bytes
    - whenever receiving data from the service, decode with base64 to get  
'''

import base64
from enum import Enum
from flask import Flask, jsonify, request, Response
from typing import Optional, Dict, List, Union
import json
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, BestAvailableEncryption, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from uuid import uuid4

app = Flask(__name__)

class FileHandler:
    @staticmethod
    def read_from_json(path: str, key: str = None) -> Union[str, Dict[str, str]]:
        with open(path, "r") as f:
            data = json.load(f)
        if key in data:
            return data[key]
        return data
    
    @staticmethod
    def read_from_file(path: str) -> str:
        with open(path, "r") as f:
            data = f.read()
        return data

    @staticmethod
    def write(path: str, data: Union[str, bytes]) -> None:
        if type(data) is bytes:
            with open(path, "wb") as f:
                f.write(data)
        elif type(data) is str:
            with open(path, "w") as f:
                f.write(data)
        else:
            raise ValueError("Data type not supported")
        
        
Keys = Enum('Keys', ['OAUTH_CREDENTIALS', 'JWT_TOKEN', 'REFRESH_TOKEN', 'REDIS_ENCRYPTION'])

KeyTypes = Enum('KeyTypes', ['ASYMMETRIC', 'SYMMETRIC'])

class Passwords:
    def __init__(self) -> None:
        self.passwords = {
            Keys.OAUTH_CREDENTIALS.name: None,
            Keys.JWT_TOKEN.name: None,
            Keys.REFRESH_TOKEN.name: None
        }
    def get_password(self, key: Keys) -> str:
        if self.passwords[key.name] is None:
            self.passwords[key.name] = FileHandler.read_from_json(os.path.join(CryptoUtils.secrets_folder, CryptoUtils.secrets_file), key.name)
            self.passwords[key.name] = self.passwords[key.name].encode('utf-8')
        
        return self.passwords[key.name]

password_obj = Passwords()

class CryptoUtils:
    secrets_folder = 'secrets/'
    secrets_file = 'secrets.json'
    key_map = {
        Keys.OAUTH_CREDENTIALS.name: KeyTypes.ASYMMETRIC,
        Keys.JWT_TOKEN.name: KeyTypes.ASYMMETRIC,
        Keys.REFRESH_TOKEN.name: KeyTypes.ASYMMETRIC,
        Keys.REDIS_ENCRYPTION.name: KeyTypes.SYMMETRIC,
        }
    
    def __init__(self) -> None:
        if not os.path.exists(CryptoUtils.secrets_folder):
            os.mkdir(CryptoUtils.secrets_folder)    
        if not os.path.exists(os.path.join(CryptoUtils.secrets_folder + CryptoUtils.secrets_file)):
            FileHandler.write(
                os.path.join(CryptoUtils.secrets_folder + CryptoUtils.secrets_file),
                json.dumps(
                    {
                        Keys.OAUTH_CREDENTIALS.name: str(uuid4()),
                        Keys.JWT_TOKEN.name: str(uuid4()),
                        Keys.REFRESH_TOKEN.name: str(uuid4())
                    }
                )
            )

    #understand how this function should look like for key tyoe of asymm vs symm, what do they need for encryption and decryption?
    @staticmethod
    def get_key(key_name: Keys, pub: bool = False, pvt:bool = False) -> bytes:
        if not os.path.exists(CryptoUtils.secrets_folder):
            
            CryptoUtils.create_secret_dir()
        if CryptoUtils.key_map[key_name.name] == KeyTypes.ASYMMETRIC:
            extension = '.pub' if pub else '.pem' if pvt else ''
            if not os.path.exists(os.path.join(CryptoUtils.secrets_folder, key_name.name + extension)):
                
                CryptoUtils.keygen(key_name=key_name, key_type=CryptoUtils.key_map[key_name.name])
            
            key = FileHandler.read_from_file(os.path.join(CryptoUtils.secrets_folder, key_name.name + extension))
            
            if type(key) is str:
                key = key.encode('utf-8')
            
            return key
        # else its a symmetric key used for redis
        
        key = CryptoUtils.keygen(key_name=key_name, key_type=CryptoUtils.key_map[key_name.name])        
        
        return key
    
    @staticmethod
    def keygen(key_name:Keys, key_type: KeyTypes) -> Union[None, bytes]:
        if not os.path.exists(CryptoUtils.secrets_folder):
            
            CryptoUtils.create_secret_dir()
        if key_type == KeyTypes.ASYMMETRIC:
            
            
            key_password = FileHandler.read_from_json(os.path.join(CryptoUtils.secrets_folder, CryptoUtils.secrets_file), key_name.name)
            key_password = key_password.encode('utf-8')
            # generating private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                )
            
            pem = private_key.private_bytes(
                encoding = Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=BestAvailableEncryption(key_password)
                )
            
            FileHandler.write(path = os.path.join(CryptoUtils.secrets_folder, key_name.name + '.pem'), data=pem)
            
            # generating public key
            public_key = private_key.public_key()
            pub = public_key.public_bytes(
                encoding = Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
                )
            
            FileHandler.write(path = os.path.join(CryptoUtils.secrets_folder, key_name.name + '.pub'), data=pub)
            
        # we do not save symmetric keys, since its only used for redis cache encryption
        elif key_type == KeyTypes.SYMMETRIC:
            key = Fernet.generate_key()
            
            return key

    # fix required: it should only accept bytes
    @staticmethod
    def encrypt(pub_key, message) -> bytes:
        if type(pub_key) is str:
            pub_key = pub_key.encode('utf-8')
        # converting into cryptography.hazmat.backends.openssl.rsa._RSAPublicKey
        pub_key = serialization.load_pem_public_key(pub_key)
        
        if type(message) is str:
            message = message.encode('utf-8')
        ciphertext = pub_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                    ),
            algorithm=hashes.SHA256(),
            label=None))
        return ciphertext
    @staticmethod
    def decrypt(ciphertext: bytes, key_name: str) -> bytes:
        '''
            - key_name: OAUTH_CREDENTIALS, JWT_TOKEN, REFRESH_TOKEN
            - To Do: private key should be fetched using key_name
        '''
        pvt_key = CryptoUtils.get_key(key_name=Keys[key_name], pvt=True)
        if type(ciphertext) is str:
            return TypeError("Ciphertext should be bytes") 

        password = password_obj.get_password(Keys[key_name])
        if type(password) is str:
            password = password.encode('utf-8')
        
        
        
        
        
        
        pvt_key = serialization.load_pem_private_key(pvt_key, password= password)
        
        plaintext = pvt_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                        )
                    )
        return plaintext

# To Do: Add a handshake between auth service and crypto service to ensure that the keys are being fetched by the right service
    # or use a shared secret between the two services
    # check if we can store the pvt key passwords in possibly a vault
@app.route("/get-jwt-pvt-key", methods = ['POST'])
def get_jwt_pvt_key():
    """
    Retrieves the private JWT key, encodes it in base64, and returns it in a JSON response.

    Returns:
        tuple: A tuple containing a JSON response with the base64-encoded JWT private key and an HTTP status code 200.
    """

    key = CryptoUtils.get_key(key_name=Keys.JWT_TOKEN, pvt=True)
    key_base64 = base64.b64encode(key).decode('utf-8')
    password = password_obj.get_password(Keys.JWT_TOKEN)
    password_base64 = base64.b64encode(password).decode('utf-8')
    return jsonify({"JWT_TOKEN": key_base64, "password": password_base64}), 200

# To Do: Add a handshake between auth service and crypto service to ensure that the keys are being fetched by the right service
    # or use a shared secret between the two services
@app.route("/get-refresh-pvt-key", methods = ['POST'])
def get_refresh_pvt_key():
    """
    Retrieves the private refresh key, encodes it in base64, and returns it in a JSON response.

    Returns:
        tuple: A tuple containing a JSON response with the base64-encoded refresh private key and an HTTP status code 200.
    """

    key = CryptoUtils.get_key(key_name=Keys.REFRESH_TOKEN, pvt=True)
    key_base64 = base64.b64encode(key).decode('utf-8')
    password = password_obj.get_password(Keys.REFRESH_TOKEN)
    password_base64 = base64.b64encode(password).decode('utf-8')
    return jsonify({"REFRESH_TOKEN": key_base64, "password": password_base64}), 200

@app.route("/get-key", methods = ['POST'])
def get_key():
    '''
    - Requires 1 argument 'key_details' containing json object with the following:
        - key_name: str 
            - 'OAUTH_CREDENTIALS' 
            - 'JWT_TOKEN'
            - 'REFRESH_TOKEN' 
            - 'REDIS_ENCRYPTION' 
    - params = {'key_details': {'key_name': 'OAUTH_CREDENTIALS'}}
    - Sample request: requests.post('http://127.0.0.1:7070/get-key', json=params)
    - Returns key in base64 encoded format
    '''
    if not request.is_json:
        return "Bad Request: Require JSON format", 400
    if 'key_details' not in request.get_json():
        return "Bad Request: key_details", 400
    if 'key_name' not in request.get_json()['key_details']:
        return "Bad Request: key_name required in key_details", 400
    if request.get_json()['key_details']['key_name'] not in Keys.__members__:
        return "Bad Request: Invalid key_name", 400
    try:
        key_details = request.get_json()['key_details']
    except (KeyError, TypeError):
        return jsonify({"error": "Bad Request: Invalid JSON format"}), 400
    key_name = key_details.get('key_name')

    if not key_name:
        return "key_name required in key_details", 400

    key = CryptoUtils.get_key(key_name=Keys[key_name], pub=True)
    key_base64 = base64.b64encode(key).decode('utf-8')
    return jsonify({f"{key_name}": key_base64}), 200

@app.route("/decrypt", methods = ['POST'])
def decrypt():
    '''
    Decrypts a given ciphertext using a specified key.
    Args:
        key_name: str
            The name of the key to use for decryption. Must be one of {'OAUTH_CREDENTIALS', '
        ciphertext: str
            The ciphertext to decrypt, encoded in base64.
    Returns:
        A JSON response containing the decrypted plaintext in base64 encoding, 
        or an error message with an appropriate HTTP status code.
    Error Responses:
        400 Bad Request:
            - If the request is not in JSON format.
            - If 'key_name' is not provided in the request data.
            - If 'key_name' is not one of {'OAUTH_CREDENTIALS', 'JWT_TOKEN', 'REFRESH_TOKEN'}.
            - If 'ciphertext' is not provided in the request data or is None.
    Success Response:
        200 OK:
            - A JSON object with the decrypted plaintext in base64 encoding.
    '''
    if not request.is_json:
        
        return "Bad Request: Require JSON format", 400
    data = request.get_json()
    if 'key_name' not in data:
        
        return "Bad Request: key_name required in key_details", 400
    
    key_name: str = data.get('key_name')

    if key_name not in {'OAUTH_CREDENTIALS', 'JWT_TOKEN', 'REFRESH_TOKEN'}:
        
        return "Bad Request: Invalid key_name", 400
    
    if 'ciphertext' not in data:
        
        return "Bad Request: ciphertext required", 400
    
    ciphertext_base64_encoded = data['ciphertext']
    if ciphertext_base64_encoded is None:
        
        return "Bad Request: ciphertext required", 400
    
    ciphertext: bytes = base64.b64decode(ciphertext_base64_encoded)
    
    # check with length of ciphertext if it is block cipher or not
    if len(ciphertext) == 256:
        plaintext: bytes = CryptoUtils.decrypt(ciphertext, key_name)
        plaintext_base64 = base64.b64encode(plaintext).decode('utf-8')
        return jsonify({"plaintext": plaintext_base64}), 200
    
    # else its a block cipher, iterate and generate plaintext
    plaintext = b''
    for i in range(0, len(ciphertext), 256):
        plaintext += CryptoUtils.decrypt(ciphertext[i:i+256], key_name)
    plaintext_base64 = base64.b64encode(plaintext).decode('utf-8')
    return jsonify({"plaintext": plaintext_base64}), 200

if __name__ == '__main__':
    CryptoUtils()
    port = 7070
    os.environ['CRYPTO_SERVICE'] = str(port)
    app.run(host="0.0.0.0", port = port)