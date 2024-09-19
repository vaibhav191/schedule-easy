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

print("Loaded .env file:", os.getenv('ENCRYPTED_GOOGLE_APP_CRED'))

class Scopes(Enum): 
    READ_PROFILE = "https://www.googleapis.com/auth/userinfo.profile"
    READ_EMAIL = "https://www.googleapis.com/auth/userinfo.email"
    FULL_CALENDAR = "https://www.googleapis.com/auth/calendar"
    FULL_EVENTS = "https://www.googleapis.com/auth/calendar.events"

class Reader:
    @staticmethod
    def from_json(path: str, key: str) -> Union[str, Dict[str, str]]:
        with open(path, "r") as f:
            data = json.load(f)
        if key in data:
                return data[key]
        return data
    
    @staticmethod
    def from_file(path: str) -> str:
        with open(path, "r") as f:
            data = f.reads()
        return data

# read port from environment variable. set env variable in docker compose.
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

# need to convert data into json so we can insert all kinds of data without having to check for types or use different insert functions.
    @staticmethod
    def insert_one(collection: Collection, data: Dict[str, Any], sensitive: bool = False) -> InsertOneResult:
        post = data
        post['last-update'] = datetime.datetime.now(tz = datetime.UTC)
        post_json = json.dumps(post)
        post_id = collection.insert_one(post_json).insert_id
        return post_id

# similarly convert fetched json and use json.loads to convert into python object.
    @staticmethod
    def fetch_one(collection: Collection, query: Dict[str, Any]) -> Dict[str, Any]:
        data_json = collection.find_one(query)
        data = json.loads(data_json)
        return data

# Implementation needed. Use JWT library to encrypt? Do not send sensitive details. Save in cookie httponly.
class JWTHandler:
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
# To do, load from environment variables instead
# push environment variables into docker compose
class KMSHandler:
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

# Must implement AWS KMS for CLIENT secrets file before creating docker image.
# Use AWS KMS to encrypt the client secrets file, store in s3.
class CredsGenerator:
    # urgent
    def __init__(self, scopes: List) -> None:
        self.scope = ['openid']
        self.scope += scopes
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

# ENVIRONMENT VARIABLES
# os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # used to ensure oauthlib can operate without https

# flask
app = Flask(__name__)
# change secret key to session secret
# app.secret_key = os.environ.get('SESSION_SECRET')
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

# once we have the credentials and email, store it in MongoDB after encryption of credentials using pub key
@app.route('/oauth2callback/<unique_id>')
def callback(unique_id):
    print("oauth2callback with unique id: ", str(unique_id))
    scope = [Scopes.READ_EMAIL.value, Scopes.READ_PROFILE.value]    
    
    rc = RedisHandler()
    data = rc.get(unique_id)
    state = data.get('state')
    request_url = data.get('request_url') 

    credgen = CredsGenerator(scope)
    # To Do: implement encryption if data is sensitive. Use Asymm encryption. Request the Key from CryptoUtils.
    #       Then store in mongodb the necessary user details
    credentials = credgen.callback(state= state, unique_id= unique_id)

    if not credentials.valid:
        return Response("Error with credentials", 401)

    # fetching email
    email = GcpService.fetch_email_id( credentials = credentials)
    data['email'] = email
    rc.set(unique_id, data)
    
    response = make_response(redirect(request_url))
    response.set_cookie('unique_id',unique_id, httponly=True)

    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", port = os.getenv('AUTH_PORT'))