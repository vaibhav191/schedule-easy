'''
To Do:
1. Move get-email to auth_service # Login won't work if google fails to respond to
    request for get-email
2. Remove gcp_service
'''

# we will continue to use crypto service since encrypting and decrypting data with AWS KMS alone can be very costly and time consuming
# due to the number of requests and network latency.
import base64
import datetime
import json
import os
from flask import Flask, redirect, request, Response, url_for, make_response
import uuid
from models.scopes import Scopes
from handlers.redis_handler import RedisHandler
from handlers.key_handler import KeyHandler
from authenticators.google_authenticator import CredsGenerator
from third_party_services.google_service import GcpService
from handlers.jwt_handler import JWTHandler
from handlers.crypto_handler import CryptoHandler
from models.keys import Keys
from handlers.mongo_handler import MongoDBHandler
from dotenv import load_dotenv


load_dotenv()
print("ENVIRONMENT VARIABLES:", os.environ)


# flask
app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET')

key_wallet = KeyHandler()
crypto_handler = CryptoHandler()
mongo_handler = MongoDBHandler()

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

    # get state and request_url from redis 
    rc = RedisHandler()
    data = rc.get(unique_id)
    state = data.get('state')
    request_url = data.get('request_url') 

    # get credentials from google
    credgen = CredsGenerator(scope)
    print("State:", state, "Unique ID:", unique_id) 
    credentials = credgen.callback(state= state, unique_id= unique_id)
    print("Credentials generated:", credentials)
    if not credentials.valid:
        print("Error with credentials")
        return Response("Error with credentials", 401)

    # fetch email from google
    print("Fetching email")
    email = GcpService.fetch_email_id( credentials = credentials)
    print("Email fetched:", email)
    data['email'] = email
    # store email in redis
    rc.set(unique_id, data)
    

    # create jwt token and refresh token
    jwt_id = str(uuid.uuid4())
    refresh_id = str(uuid.uuid4())
    user = email
    jwt_pvt_key, jwt_key_password = key_wallet.get_pvt_key(Keys.JWT_TOKEN)
    refresh_pvt_key, refresh_key_password = key_wallet.get_pvt_key(Keys.REFRESH_TOKEN) 
    jwt_token, refresh_token = JWTHandler.create_tokens(user, jwt_id, jwt_pvt_key, jwt_key_password, refresh_id, refresh_pvt_key, refresh_key_password)

    # encrypt credentials
    credentials_json = credentials.to_json()
    credentials_bytes = credentials_json.encode('utf-8')
    print("Credentials bytes:", credentials_bytes)
    oauth_pub_key = key_wallet.get_pub_key(Keys.OAUTH_CREDENTIALS)
    credentials_encrypted = crypto_handler.asymm_encrypt(credentials_bytes, oauth_pub_key)
    credentials_encrypted_b64 = base64.b64encode(credentials_encrypted).decode('utf-8')
    print("Credentials encrypted b64:", credentials_encrypted_b64)
    # initialize mongo
    print("Initializing mongo")
    db = mongo_handler.get_client('auth')
    collection = mongo_handler.get_collection(db, 'user_data')
    query = {'email': email}
    user_record = mongo_handler.fetch_one(collection, query)
    print("User record:", user_record)
    if not user_record:
        print("User record not found in mongo")
        user_record = {
            'email': email,
            'jwt-id': jwt_id,
            'refresh-id': refresh_id,
            'credentials_encrypted': credentials_encrypted_b64,
            'registered-date': str(datetime.datetime.now(datetime.timezone.utc)),
            'last-update': str(datetime.datetime.now(datetime.timezone.utc))
        }
        post_id = mongo_handler.insert_one(collection, user_record)
        if not post_id:
            print("Error inserting user record in mongo")
            return Response("Error inserting user record in mongo", 500)
        else:
            print("User record inserted in mongo")

    else:
        print("User record found in mongo")
        user_record['jwt-id'] = jwt_id
        user_record['refresh-id'] = refresh_id
        user_record['credentials_encrypted'] = credentials_encrypted_b64
        user_record['last-update'] = str(datetime.datetime.now(datetime.timezone.utc))

        post_id = mongo_handler.update_one(collection, query, user_record)
        print("User record updated in mongo")


    print("User record:", user_record)
    print("Post ID:", post_id)
    print("Unique ID:", unique_id)
    response = make_response(redirect(request_url))
    response.set_cookie('unique_id',unique_id, httponly=True)
    response.set_cookie('jwt_token', jwt_token, httponly=True)
    response.set_cookie('refresh_token', refresh_token, httponly=True)

    return response



if __name__ == '__main__':
    app.run(host="0.0.0.0", port = os.getenv('AUTH_PORT'))