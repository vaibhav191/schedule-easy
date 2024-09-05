# Crypto should be a service
# To Do in production: Leverage AWS KMS to fetch keys
# Fetches keys from json files
# Caller should know which key they want to fetch
# 1. Asymm encryption for Google Oauth Credentials
# 2. Asymm encryption for jwt token
# 3. Asymm encryption for jwt refresh token
# 4. Symm encryption with real time key generation for redis cache data (stores keys themselves 
# so many fetches arent required)
# Let's use ES256 - ECDSA signature algorithm using SHA-256 hash algorithm
# https://pyjwt.readthedocs.io/en/stable/algorithms.html#asymmetric-public-key-algorithms

'''
private_key = ec.generate_private_key(ec.SECP384R1())
pem = private_key.private_bytes(encoding = Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=BestAvailableEncryption(b'password'))

pem_pub = public_key.public_bytes(encoding = Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)

encoded = jwt.encode({"Some":"data"}, serialization.load_pem_private_key(pem,password=passphrase,backend=default_backend()), algorithm="ES256K")
jwt.decode(encoded,pem_pub, "ES256K", options={"verify_signature":True})
'''

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
        
        
Keys = Enum('Keys', ['OAUTH_CREDENTIALS', 'JWT_TOKEN', 'REFRESH_TOKEN', 'REDIS_ENCRYPTION'])

KeyTypes = Enum('KeyTypes', ['ASYMMETRIC', 'SYMMETRIC'])

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
            return key
        # else its a symmetric key used for redis
        key = CryptoUtils.keygen(key_name=key_name, key_type=CryptoUtils.key_map[key_name.name])        
        return key
    
    #To Do: leverage https://safecurves.cr.yp.to/ to write a safe EC private key generator
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
            # FileHandler.write(key_name.value, key)

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
    def decrypt(pvt_key, ciphertext: bytes, key_name: str) -> bytes:
        '''
        key_name: OAUTH_CREDENTIALS, JWT_TOKEN, REFRESH_TOKEN
        '''
        if type(pvt_key) is str:
            pvt_key = pvt_key.encode('utf-8')
        
        password = FileHandler.read_from_json(os.path.join(CryptoUtils.secrets_folder, CryptoUtils.secrets_file),key_name)
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

@app.route("/get-key", methods = ['GET'])
def get_key():
    '''
    Requires 1 argument 'key_details' containing json object with the following:
    key_name: example - 'OAUTH_CREDENTIALS'
            OAUTH_CREDENTIALS 
            JWT_TOKEN 
            REFRESH_TOKEN 
            REDIS_ENCRYPTION 
    pub: bool
    pvt: bool
    params = {'key_details': json.dumps({'key_name': 'OAUTH_CREDENTIALS', 'pvt':True})}
    requests.get('http://127.0.0.1:7070/get-key', params=params)
    '''
    if 'key_details' not in request.args:
        return "Bad Request: Require key details", 400
    try:
        key_details = json.loads(request.args['key_details'])
    except json.JSONDecodeError:
        return jsonify({"error": "Bad Request: Invalid JSON format"}), 400
    key_name = key_details.get('key_name')
    pub = key_details.get('pub', False)
    pvt = key_details.get('pvt', False)

    if not key_name:
        return "key_name required in key_details", 400

    key = CryptoUtils.get_key(key_name=Keys[key_name], pub=pub, pvt=pvt)

    return key, 200

if __name__ == '__main__':
    CryptoUtils()
    port = 7070
    os.environ['CRYPTO_SERVICE'] = str(port)
    app.run(host="0.0.0.0", port = port)