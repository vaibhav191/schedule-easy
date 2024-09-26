'''
Google Oauth Mechanism
1. /login initiates google oauth
    calls /authorize with scope = profile and read_email
    a. /authorize
        /login calls authorize with limited scope (profile)
            with callback of oauth2callback
        Authorize initiates flow which will redirect user to choose
            a google account followed by the authorization approval
        Once approved user is redirected to the callback url i.e. oauth2callback
            with the authorization code
    b. /oauth2callback
        Receives the authorization code in the request url
        Uses the authorization state and code to create flow object which
            can then be used to fetch_token.
        Once fetched, we can call flow.credentials to obtain the credentials.
    -> Store credentials in  Mongo.
    -> leverage token to generate  and send JWT token and a refresh token for the user.
    -> Send user back to request url with the token.

JWT Token Mechanism
2.1 /validate to be implemented by every microservice, they shall store the public key
    for jwt and refresh thn in their local cache.

    /get-jwt and /get-refresh-tkn
    need to be end points since each microservice will have it's own validate function
    which might need to call /get-jwt and /get-refresh-tkn when they expire.
    
    a. /get-jwt
    -> Use Asymm encryption, signed with private-key
    -> Message body: 
        # RFC 7519 - Registered Claim Names
        iss (Issuer)
        sub (Subject)
        aud (Audience)
        exp (Expiration Time)
        nbf (Not Before)
        iat (Issued At)
        jti (JWT ID)
        
        # private claims
        cdi (Credentials ID) 
        atkn (Auth Token)

    b. /get-refresh-tkn
        -> identical to get-jwt, signed with different private-key

    c. /validate
        -> To be implemented by every microservice
        -> False if: # user is asked to login again
            No Refresh or No JWT
            JWT != Refresh
        -> if expired:
            call /refresh
        -> else True
    d. /refresh
        -> calls create-jwt and create-refresh-tkn

Mongo
UserDetails:
    1. username (email fetched from get-email) # encrypted
    2. auth credentials (as a json file object - https://ai.google.dev/palm_docs/oauth_quickstart#:~:text=Authorize%20credentials%20for%20a%20desktop%20application%201%20In,download%20button%20to%20save%20the%20JSON%20file.%20)
        encrypt using another set of pub-pvt key, use pub key to encrypt, kept with
        auth server.
    3. jwt id
    4. jwt tkn
    # jwts are signed using pvt keys, kept on aws (stored in cache). pub key fetched
    # from aws

! we will encrypt all data inside mongo using asymm key, these keys will be in aws kms
! to limit the number of requests to aws kms, microservices will save these data in Redis
! Data saved in Redis will be encrypted through symm encryption Fernet key.
! Fernet key will live with the program.
! Each redis data is prefixed by the microservice name and time it was created
! service only tries to look up redis data using its own key and data- name+time
! if the data is no longer accessible, it generates a new key, deletes name+time data
! and create new instance of name+time data and stores the data for later use.

! for the above to work, every microservice that needs access to encrypted data 
! will need it's own redis access, redis remove Fernet key generate

To Do:
1. Move get-email to auth_service # Login won't work if google fails to respond to
    request for get-email
2. Remove gcp_service

'''

# we will continue to use crypto service since encrypting and decrypting data with AWS KMS alone can be very costly and time consuming
# due to the number of requests and network latency.
import base64
from enum import Enum
from flask import Flask, redirect, request, Response, url_for, session, make_response
import requests
import os
# pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import requests
import json
from redis import Redis, client
from typing import Optional, Union, List, Dict, Any
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.results import InsertOneResult
import datetime
import boto3
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
print("ENVIRONMENT VARIABLES:", os.environ)

class Scopes(Enum): 
    READ_PROFILE = "https://www.googleapis.com/auth/userinfo.profile"
    READ_EMAIL = "https://www.googleapis.com/auth/userinfo.email"
    FULL_CALENDAR = "https://www.googleapis.com/auth/calendar"
    FULL_EVENTS = "https://www.googleapis.com/auth/calendar.events"


class Keys(Enum):
    OAUTH_CREDENTIALS, JWT_TOKEN, REFRESH_TOKEN, REDIS_ENCRYPTION = range(4)

class KeyTypes(Enum):
    pub, pvt, symmetric = range(3)

class CryptoHandler:
    """
    CryptoHandler class provides methods to handle cryptographic operations such as key retrieval, encryption, and decryption.
    Attributes:
        key_types (dict): A dictionary mapping key names to their types (public, private, symmetric).
        Crypto_host (str): The host address of the crypto service.
        Crypto_port (str): The port number of the crypto service.
    Methods:
        get_public_key(key_name: Keys) -> bytes:
            Retrieves the public key for the given key name from the crypto service.
            Args:
                key_name (Keys): The name of the key to retrieve.
            Returns:
                bytes: The public key in bytes.
            Raises:
                Exception: If the key name is invalid or the public key is not available.
        get_symmetric_key(key_name: Keys) -> bytes:
            Retrieves the symmetric key for the given key name from the crypto service.
            Args:
                key_name (Keys): The name of the key to retrieve.
            Returns:
                bytes: The symmetric key in bytes.
            Raises:
                Exception: If the key name is invalid or the symmetric key is not available.
        asymm_encrypt(data: bytes, key: bytes) -> bytes:
            Encrypts the given data using the provided public key.
            Args:
                data (bytes): The data to encrypt.
                key (bytes): The public key to use for encryption.
            Returns:
                bytes: The encrypted data.
            Raises:
                Exception: If the key or data is invalid, or encryption fails.
        asymm_decrypt(ciphertext: bytes, key_name: Keys) -> bytes:
            Decrypts the given ciphertext using the private key stored in the crypto service.
            Args:
                ciphertext (bytes): The data to decrypt.
                key_name (Keys): The name of the key to use for decryption.
            Returns:
                bytes: The decrypted data.
            Raises:
                Exception: If the key name or data is invalid, or decryption fails.
        symm_encrypt(data: bytes, key: bytes) -> bytes:
            Encrypts the given data using the provided symmetric key.
            Args:
                data (bytes): The data to encrypt.
                key (bytes): The symmetric key to use for encryption.
            Returns:
                bytes: The encrypted data.
        symm_decrypt(data: bytes, key: bytes) -> bytes:
            Decrypts the given data using the provided symmetric key.
            Args:
                data (bytes): The data to decrypt.
                key (bytes): The symmetric key to use for decryption.
            Returns:
                bytes: The decrypted data.
        sign(data: bytes) -> bytes:
            Signs the given data.
            Args:
                data (bytes): The data to sign.
            Returns:
                bytes: The signature.
        verify(data: bytes) -> bytes:
            Verifies the given data.
            Args:
                data (bytes): The data to verify.
            Returns:
                bytes: The verification result.
    """

    key_types = {
        Keys.OAUTH_CREDENTIALS: {KeyTypes.pub, KeyTypes.pvt},
        Keys.JWT_TOKEN: {KeyTypes.pub, KeyTypes.pvt},
        Keys.REFRESH_TOKEN: {KeyTypes.pub, KeyTypes.pvt},
        Keys.REDIS_ENCRYPTION: {KeyTypes.symmetric},
    }

    Crypto_host = os.getenv('CRYPTO_HOST')
    Crypto_port = os.getenv('CRYPTO_PORT')

    @staticmethod
    def get_public_key(key_name: Keys) -> bytes:
        """
        Retrieves the public key for the given key name from the crypto service.
        Args:
            key_name (Keys): The name of the key to retrieve.
        Returns:
            bytes: The public key in bytes.
        Raises:
            Exception: If the key_name is invalid or the public key is not available.
            Exception: If the request to the crypto service fails.
        """
        if key_name not in CryptoHandler.key_types:
            raise Exception("Invalid key_name")
        if KeyTypes.pub not in CryptoHandler.key_types[key_name]:
            raise Exception("Public key not available for the given key_name")
        
        url = f"http://{CryptoHandler.Crypto_host}:{CryptoHandler.Crypto_port}/get-key"
        key_details = {'key_name': key_name.name, 
                    }
        response = requests.post(url, json = {'key_details': key_details})
        if response.status_code == 200:
            print(f"Key received from crypto service, response: {response.content}")
            if key_name.name in response.json():
                key_b64 = response.json()[key_name.name]
                return base64.b64decode(key_b64)
        else:
            print(f"Failed to get key from crypto service, response: {response.content}, status code: {response.status_code}")  
            raise Exception("Failed to get key from crypto service")
    
    @staticmethod
    def get_private_key(key_name: Keys) -> bytes:
        """
        Retrieves the private key for the specified key name from the crypto service.
        Args:
            key_name (Keys): The name of the key to retrieve. Must be a member of the Keys enum.
        Returns:
            bytes: The private key in bytes.
        Raises:
            Exception: If the key_name is invalid or if the private key is not available for the given key_name.
            Exception: If the request to the crypto service fails.
        Notes:
            - The private key requested must either be of type REFRESH_TOKEN or JWT_TOKEN.
            - The function constructs the endpoint URL based on the key_name and sends a POST request to the crypto service.
            - If the response status code is 200, it decodes the base64-encoded key from the response and returns it.
            - If the response status code is not 200, it raises an exception.
        """
        if key_name not in CryptoHandler.key_types:
            raise Exception("Invalid key_name")
        if KeyTypes.pvt not in CryptoHandler.key_types[key_name]:
            raise Exception("Private key not available for the given key_name")
        
        if key_name == Keys.REFRESH_TOKEN:
            endpoint = '/get-refresh-pvt-key'
        elif key_name == Keys.JWT_TOKEN:
            endpoint = '/get-jwt-pvt-key'
        else:
            print("Invalid key_name:", key_name)
            raise Exception("Invalid key_name")    
        url = f"http://{CryptoHandler.Crypto_host}:{CryptoHandler.Crypto_port}" + endpoint
        response = requests.post(url)
        if response.status_code == 200:
            print(f"Key received from crypto service, response: {response.content}")
            if key_name.name in response.json():
                key_b64 = response.json()[key_name.name]
                return base64.b64decode(key_b64)
        else:
            print(f"Failed to get key from crypto service, response: {response.content}, status code: {response.status_code}")  
            raise Exception("Failed to get key from crypto service")

    @staticmethod
    def get_symmetric_key(key_name: Keys) -> bytes:
        """
        Retrieves a symmetric key from the crypto service.
        Args:
            key_name (Keys): The name of the key to retrieve.
        Returns:
            bytes: The symmetric key in bytes.
        Raises:
            Exception: If the key_name is invalid or if the symmetric key is not available for the given key_name.
            Exception: If the request to the crypto service fails.
        Notes:
            - The function checks if the provided key_name is valid and if a symmetric key is available for it.
            - It sends a POST request to the crypto service to retrieve the key.
            - If the request is successful and the key is found in the response, it decodes the key from base64 and returns it.
            - If the request fails, it raises an exception with the appropriate error message.
        """
        if key_name not in CryptoHandler.key_types:
            raise Exception("Invalid key_name")
        if KeyTypes.symmetric not in CryptoHandler.key_types[key_name]:
            raise Exception("Symmetric Key not available for the given key_name")
        
        url = f"http://{CryptoHandler.Crypto_host}:{CryptoHandler.Crypto_port}/get-key"
        key_details = {'key_name': key_name.name}
        response = requests.post(url, params = {'key_details': key_details})
        if response.status_code == 200:
            print(f"Key received from crypto service, response: {response.content}")
            if key_name.name in response.json():
                key_b64 = response.json()[key_name.name]
                return base64.b64decode(key_b64)
        else:
            print(f"Failed to get key from crypto service, response: {response.content}, status code: {response.status_code}")  
            raise Exception("Failed to get key from crypto service")

    @staticmethod
    def asymm_encrypt(data: bytes, key: bytes ) -> bytes:
        """
        Encrypts the given data using the provided public key with asymmetric encryption.
        Args:
            data (bytes): The data to be encrypted. Must be of type bytes.
            key (bytes): The public key used for encryption. Must be of type bytes.
        Returns:
            bytes: The encrypted data.
        Raises:
            Exception: If the key is not of type bytes.
            Exception: If the data is not of type bytes.
            Exception: If the public key serialization fails.
            Exception: If the encryption process fails.
        """
        
        if not key or type(key) is not bytes:
            raise Exception("Key must be of type bytes")
        if type(data) is not bytes:
            raise Exception("Data must be of type bytes")
        try:
            public_key = serialization.load_pem_public_key(key)
        except Exception as e:
            raise Exception("Public key serialization failed, check key")
        try:
            ciphertext = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise Exception("Failed to encrypt data. Check data.")
        return ciphertext

    @staticmethod
    def asymm_decrypt(ciphertext: bytes, key_name: Keys) -> bytes:
        """
        Decrypts the given ciphertext using an asymmetric decryption method.
        Args:
            ciphertext (bytes): The encrypted data to be decrypted.
            key_name (Keys): The name of the key to be used for decryption. Must be one of Keys.OAUTH_CREDENTIALS, Keys.JWT_TOKEN, or Keys.REFRESH_TOKEN.
        Returns:
            bytes: The decrypted plaintext.
        Raises:
            Exception: If key_name is invalid or not provided.
            Exception: If ciphertext is not of type bytes.
            Exception: If the private key is not available for the given key_name.
            Exception: If the decryption service fails to return a valid response.
        """
        
        if not key_name or type(key_name) is not Keys or key_name not in {Keys.OAUTH_CREDENTIALS, Keys.JWT_TOKEN, Keys.REFRESH_TOKEN}:
            raise Exception("Invalid key_name")
        if type(ciphertext) is not bytes:
            raise Exception("Data must be of type bytes")
        if KeyTypes.pvt not in CryptoHandler.key_types[key_name]:
            raise Exception("Private key not available for the given key_name")

        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

        url = f"http://{CryptoHandler.Crypto_host}:{CryptoHandler.Crypto_port}/decrypt"
        key_details = {'key_name': key_name.name, 'ciphertext': ciphertext_b64}
        print("Key Details:", key_details)
        response = requests.post(url, json = key_details)
        print("Response:", response.content, response.status_code)
        if response.status_code == 200:
            print(f"Data received from crypto service, response: {response.content}")
            if 'plaintext' in response.json():
                plaintext_b64 = response.json()['plaintext']
                return base64.b64decode(plaintext_b64)
        else:
            print(f"Failed to get data from crypto service, response: {response.content}, status code: {response.status_code}")  
            raise Exception("Failed to get data from crypto service")
    
    def symm_encrypt(data: bytes, key: bytes) -> bytes:
        """
        Encrypts the given data using symmetric encryption with the provided key.
        Args:
            data (bytes): The data to be encrypted.
            key (bytes): The encryption key.
        Returns:
            bytes: The encrypted data.
        """
        if not key or type(key) is not bytes:
            print("Key must be of type bytes", type(key))
            raise Exception("Key must be of type bytes") 
        if type(data) is not bytes:
            print("Data must be of type bytes", type(data))
            raise Exception("Data must be of type bytes")
        f = Fernet(key)
        return f.encrypt(data)

    def symm_decrypt(data: bytes, key: bytes) -> bytes:
        """
        Decrypts the given data using the provided symmetric key.

        Args:
            data (bytes): The encrypted data to be decrypted.
            key (bytes): The symmetric key used for decryption.

        Returns:
            bytes: The decrypted data.
        """
        f = Fernet(key)
        return f.decrypt(data)

    @staticmethod
    def sign(data: bytes) -> bytes:
        pass

    @staticmethod
    def verify(data: bytes) -> bytes:
        pass


class MongoDBHandler:
    address = os.getenv('MONGO_ADDRESS')
    port = os.getenv('MONGO_PORT')

    @staticmethod
    def get_client(db: str) -> Database:
        client: MongoClient = MongoClient(MongoDBHandler.address + ':' + MongoDBHandler.port)
        return client[db]
    
    @staticmethod
    def get_collection(db: Database, collection_name: str) -> Collection:
        collection: Collection = db[collection_name]
        return collection

    @staticmethod
    def insert_one(collection: Collection, data: Dict[str, Any]) -> InsertOneResult:
        post = data
        post['last-update'] = datetime.datetime.now(tz = datetime.UTC)
        post_json = json.dumps(post)
        post_id = collection.insert_one(post_json).insert_id
        return post_id

    @staticmethod
    def fetch_one(collection: Collection, query: Dict[str, Any]) -> Dict[str, Any]:
        data_json = collection.find_one(query)
        data = json.loads(data_json)
        return data

# Implementation needed. Use JWT library to encrypt? Do not send sensitive details. Save in cookie httponly.
class JWTHandler:
    # authorization server ,ust verify that the user who is requesting for
    # refresh token is the same user who was issued the JWT token.
    # issue a new refresh token whenever refresh is called. (refresh token rotation)
    # If a refresh token is
    #    compromised and subsequently used by both the attacker and the
    #    legitimate client, one of them will present an invalidated refresh
    #    token, which will inform the authorization server of the breach.
    #   The authorization server can then revoke the refresh token.
    # access token should be short lived, refresh token should be long lived.
    # access token should only be requested with the minimum scope required.
    @staticmethod
    def create_jwt_token():
        pass
    @staticmethod
    def create_refresh_token():
        pass
    def validate_jwt_token():
        pass
    def validate_refresh_token():
        pass

# what else do we need it for except login? maybe some active session details?
class RedisHandler:
    def __init__(self) -> None:
        self.host = os.getenv('REDIS_HOST', 'redis')
        self.port = os.getenv('REDIS_PORT')
        self.decode_responses = True
        self.redis_client = Redis(host = self.host, port = self.port, decode_responses= self.decode_responses)

    def get_client(self) -> client.Redis:
        return self.redis_client

    def set(self, key: str, data: Union[str, Dict]) -> bool:
        data = json.dumps(data)
        print("Redis set Data:", data)
        return self.redis_client.set(key, data)
    
    def get(self, key: Union[str, Dict]) -> Union[str, Dict[str, str]]:
        print("Redis get key:", key)
        data = self.redis_client.get(key)
        data = json.loads(data)
        print("Redis Data received:", data)
        return data
    
    def delete(self, key) -> None:
        self.redis_client.delete(key)

class GcpService:
    @staticmethod
    def fetch_email_id(credentials: Credentials) ->  str:
        # API name and version
        API_SERVICE_NAME = 'people'
        api_version = 'v1'

        if not credentials.valid:
            raise Exception("Invalid Credentials")        

        # Service Object
        service = build(API_SERVICE_NAME , api_version, credentials=credentials)
        people_obj = service.people()
        
        # Query
        query = people_obj.get(resourceName = 'people/me', personFields = 'emailAddresses')
        
        # Result
        res: Dict[str: Any] = query.execute()
        
        # Fetch
        email: str = next((email['value'] for email in res['emailAddresses'] if email['metadata']['primary']), None) 

        return email

# AWS KMS
class KMSHandler:
    '''
        Remember, KMSHandler does not need KMS Access and secret key when running on AWS through IAM roles.
    '''
    def __init__(self) -> None:
        self.access_key = os.getenv('AUTH_KMS_ACCESS_KEY')
        self.secret_key = os.getenv('AUTH_KMS_SECRET_KEY')
        self.region = os.getenv('AUTH_KMS_REGION')
        self.keyID = os.getenv('AUTH_APP_CREDENTIALS_KEYID')
        self.client = boto3.client('kms', region_name = self.region, aws_access_key_id = self.access_key, aws_secret_access_key = self.secret_key)
    
    def encrypt(self, data: bytes) -> bytes:
        resp = self.client.encrypt(KeyId = self.keyID, Plaintext = data, EncryptionContext = {'context': 'google_app_cred'})
        if 'CiphertextBlob' in resp:
            return resp['CiphertextBlob']
        return None

    def decrypt(self, data: bytes) -> bytes:
        resp = self.client.decrypt(CiphertextBlob = data, KeyId = self.keyID, EncryptionContext = {'context': 'google_app_cred'})
        if 'Plaintext' in resp:
            return resp['Plaintext']
        return None

class CredsGenerator:
    def __init__(self, scopes: List) -> None:
        self.scope = ['openid']
        self.scope += scopes
        
        # decrypt the encrypted app credentials using AWS KMS
        encrypted_app_cred = os.getenv("ENCRYPTED_GOOGLE_APP_CRED")
        encrypted_app_cred_bytes = base64.b64decode(encrypted_app_cred)
        kms = KMSHandler()
        self.CLIENT_SECRETS: str = kms.decrypt(encrypted_app_cred_bytes).decode('utf-8')
        self.CLIENT_SECRETS: Dict[str: str] = json.loads(self.CLIENT_SECRETS)

    def authorize(self, unique_id) -> None: 
        # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
        self.CLIENT_SECRETS, scopes=self.scope)

        # The URI created here must exactly match one of the authorized redirect URIs
        # for the OAuth 2.0 client, which you configured in the API Console. If this
        # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
        # error.
        flow.redirect_uri = url_for('callback', unique_id = unique_id, _external=True)

        self.authorization_url, self.state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

        print("authorization_URL:", self.authorization_url)
        return redirect(self.authorization_url)
    
    def callback(self, state, unique_id) -> Credentials:
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            self.CLIENT_SECRETS, self.scope, state = state 
        )
        flow.redirect_uri = url_for('callback',unique_id = unique_id, _external = True)
        authorization_response: str = request.url
        flow.fetch_token(authorization_response = authorization_response)

        self.credentials = flow.credentials
        return self.credentials

# flask
app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET')

# change unique_id to session_id
@app.route('/')
def home():
    unique_id = request.cookies.get('unique_id')
    if not unique_id:
        return redirect(url_for('login', next = request.url))
    
    rc = RedisHandler()
    data = rc.get(unique_id)
    
    return Response(f"OK {data.get('email')}", 200)

@app.route('/login')
def login():
    scope = [Scopes.READ_EMAIL.value, Scopes.READ_PROFILE.value]
    unique_id = str(uuid.uuid4())
    credgen = CredsGenerator(scope)
    credgen.authorize(unique_id)
    
    data = {'state': credgen.state, 'request_url': request.args.get('next')}
    
    rc = RedisHandler()
    rc.set(unique_id, data)
    
    authorization_url = credgen.authorization_url
    return redirect(authorization_url)

@app.route('/oauth2callback/<unique_id>')
def callback(unique_id):
    print("oauth2callback with unique id: ", str(unique_id))
    scope = [Scopes.READ_EMAIL.value, Scopes.READ_PROFILE.value]    
    
    rc = RedisHandler()
    data = rc.get(unique_id)
    state = data.get('state')
    request_url = data.get('request_url') 

    credgen = CredsGenerator(scope)
    print("State:", state, "Unique ID:", unique_id) 
    credentials = credgen.callback(state= state, unique_id= unique_id)
    print("Credentials generated:", credentials)
    if not credentials.valid:
        print("Error with credentials")
        return Response("Error with credentials", 401)

    print("Fetching email")
    email = GcpService.fetch_email_id( credentials = credentials)
    print("Email fetched:", email)
    data['email'] = email
    rc.set(unique_id, data)
    
    # store details in mongo
        # check if email already exists in mongo
        # if not, insert email, credentials, jwt, refresh token, last-update
        # if yes, update jwt, refresh token, last-update
        # encrypt credentials, jwt, refresh token
    

    response = make_response(redirect(request_url))
    response.set_cookie('unique_id',unique_id, httponly=True)

    return response

class KeyWallet:
    """
    A class to manage and retrieve cryptographic keys.

    Attributes:
    -----------
    keys : dict
        A dictionary that maps key names (from the Keys enum) to their corresponding cryptographic keys.

    Methods:
    --------
    __init__():
        Initializes the KeyWallet with a dictionary of keys set to None.
    
    get_key(key_name: Keys) -> bytes:
        Retrieves the public key for the given key name. If the key is not already cached, it fetches the key using the CryptoHandler(which requests the same from crypto_service) and stores it in the keys dictionary.
    """
    def __init__(self):
        self.pub_keys = {x.name:None for x in Keys}
        self.pvt_keys = {x.name for x in (Keys.REFRESH_TOKEN, Keys.JWT_TOKEN)}
    def get_pub_key(self, key_name: Keys) -> bytes:
        if not self.pub_keys[key_name.name]:
            self.pub_keys[key_name.name] = CryptoHandler.get_public_key(key_name)
        return self.keys[key_name.name]
    def get_pvt_key(self, key_name: Keys) -> bytes:
        if key_name.name not in self.pvt_keys:
            print("Invalid key_name:", key_name)
            raise Exception("Invalid key_name")
        return CryptoHandler.get_private_key(key_name)


key_wallet = KeyWallet()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port = os.getenv('AUTH_PORT'))