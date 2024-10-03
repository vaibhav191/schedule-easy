'''
To Do:
1. Implement proper validation of JWT tokens and refresh tokens.
2. Implement /refresh endpoint to refresh JWT tokens.
'''

# we will continue to use crypto service since encrypting and decrypting data with AWS KMS alone can be very costly and time consuming
# due to the number of requests and network latency.
import base64
import datetime
import json
import os
from flask import Flask, redirect, request, Response, url_for, make_response
import uuid

import requests
from models.scopes import Scopes
from handlers.redis_handler import RedisHandler
from handlers.key_handler import KeyHandler
from authenticators.google_authenticator import CredsGenerator
from third_party_services.google_service import GcpService
from handlers.jwt_handler import JWTHandler
from handlers.crypto_handler import CryptoHandler
from models.keys import Keys
from handlers.mongo_handler import MongoDBHandler
import jwt
import sys
import logging


app = Flask(__name__)
app.secret_key = os.getenv('SESSION_SECRET')

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
key_wallet = KeyHandler()
crypto_handler = CryptoHandler()
mongo_handler = MongoDBHandler()
rc = RedisHandler()


def validate_tokens(f):
    def wrapper(*args, **kwargs):
        app.logger.debug(f"{validate_tokens.__name__}: Validating tokens.")
        # check if session has jwt, refresh token, unique id
        app.logger.debug(f"{wrapper.__name__}: Request: {request.host}")
        refresh_token = request.cookies.get('refresh_token')
        app.logger.debug(f"{wrapper.__name__}: Refresh Token: {refresh_token[:10] if refresh_token else 'Not Found'}")
        jwt_token = request.cookies.get('jwt_token')
        app.logger.debug(f"{wrapper.__name__}: JWT Token: {jwt_token[:10] if jwt_token else 'Not Found'}")
        unique_id = request.cookies.get('unique_id')
        app.logger.debug(f"{wrapper.__name__}: Unique ID: {unique_id if unique_id else 'Not Found'}")
        # Do we need to check for unique_id? since redis is optional storage
        # if we do not have unique_id available just use mongo for data instead
        if not refresh_token or not jwt_token:
            return redirect(url_for('login'))
        app.logger.debug(f"{wrapper.__name__}: Unique ID check: {unique_id}")
        if not unique_id:
            app.logger.debug(f"{wrapper.__name__}: Unique ID not found, setting.")
            email = jwt.decode(jwt_token, jwt_key, algorithms=['RS256'], verify=False)['sub']
            unique_id = str(uuid.uuid4())
            data = {'email': email}
            rc.set(unique_id, data)
        app.logger.debug(f"{wrapper.__name__}: Unique ID: {unique_id}")
        # check if jwt is valid
        app.logger.debug(f"{wrapper.__name__}: Checking if jwt is valid.")
        jwt_key = key_wallet.get_pub_key(Keys.JWT_TOKEN)
        jwt_token_valid = JWTHandler.validate_jwt_token(jwt_token, jwt_key, app.logger)
        app.logger.debug(f"{wrapper.__name__}: JWT Valid: {jwt_token_valid}")
        if not jwt_token_valid:
            app.logger.debug(f"{wrapper.__name__}: JWT token not valid.")
            # if not valid, check if refresh token is valid
            refresh_key = key_wallet.get_pub_key(Keys.REFRESH_TOKEN)
            refresh_token_valid = JWTHandler.validate_refresh_token(refresh_token, refresh_key, app.logger)
            app.logger.debug(f"{wrapper.__name__}: Refresh token valid?: {refresh_token_valid}")
            if not refresh_token_valid:
                return redirect(url_for('login'))
            # if refresh token is valid, call refresh token endpoint
            app.logger.debug(f"{wrapper.__name__}: Calling refresh token endpoint.")
            cookies = {'refresh_token': refresh_token, 'unique_id': unique_id, 'jwt_token': jwt_token}
            app.logger.debug(f"{wrapper.__name__}: Using cookies: {cookies}")
            response = requests.post(url_for(refresh), cookies=cookies)
            app.logger.debug(f"{wrapper.__name__}: Response Statuc: {response.status_code}, Refresh content: {response.content}")
            if response.status_code != 200:
                return redirect(url_for('login'))

            new_jwt_token = response.cookies.get('jwt_token')
            new_refresh_token = response.cookies.get('refresh_token')
            response = make_response(redirect(url_for(f.__name__)))
            # set new jwt token and refresh token in cookies
            response.set_cookie('jwt_token', new_jwt_token)
            response.set_cookie('refresh_token', new_refresh_token)
            response.set_cookie('unique_id', unique_id)
            return response, 200
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


@app.route('/login')
def login():
    scope = [Scopes.READ_EMAIL.value, Scopes.READ_PROFILE.value, Scopes.FULL_CALENDAR.value]
    unique_id = str(uuid.uuid4())
    credgen = CredsGenerator(scope)
    credgen.authorize(unique_id)
    app.logger.debug(f"{login.__name__}: request args: {request.args}")
    data = {'state': credgen.state, 'request_url': request.args.get('next'), 'scopes': scope}
    app.logger.debug(f"{login.__name__}: Data: {data}") 
    rc = RedisHandler()
    rc.set(unique_id, data, app.logger)
    
    authorization_url = credgen.authorization_url
    return redirect(authorization_url)

@app.route('/oauth2callback/<unique_id>')
def callback(unique_id):
    app.logger.debug(f"{callback.__name__}: oauth2callback with unique id: {unique_id}")
    # get state and request_url from redis 
    data = rc.get(unique_id, app.logger)
    state = data.get('state')
    request_url = data.get('request_url') 
    
    # scope = [Scopes.READ_EMAIL.value, Scopes.READ_PROFILE.value]    
    scope = rc.get(unique_id, app.logger).get('scopes')
    app.logger.debug(f"{callback.__name__}: Scope: {scope}")
    
    # get credentials from google
    credgen = CredsGenerator(scope)
    app.logger.debug(f"{callback.__name__}: State: {state}, Unique ID: {unique_id}") 
    credentials = credgen.callback(state= state, unique_id= unique_id)
    app.logger.debug(f"{callback.__name__}: Credentials generated: {credentials}")
    if not credentials.valid:
        app.logger.debug(f"{callback.__name__}: Error with credentials")
        return Response("Error with credentials", 401)

    # fetch email from google
    app.logger.debug(f"{callback.__name__}: Fetching email")
    email = GcpService.fetch_email_id( credentials = credentials)
    app.logger.debug(f"{callback.__name__}: Email fetched: {email}")
    data['email'] = email
    # store email in redis
    rc.set(unique_id, data, app.logger)
    

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
    app.logger.debug(f"{callback.__name__}: Credentials bytes: {credentials_bytes}")
    oauth_pub_key = key_wallet.get_pub_key(Keys.OAUTH_CREDENTIALS)
    credentials_encrypted = crypto_handler.asymm_encrypt(credentials_bytes, oauth_pub_key)
    credentials_encrypted_b64 = base64.b64encode(credentials_encrypted).decode('utf-8')
    app.logger.debug(f"{callback.__name__}: Credentials encrypted b64: {credentials_encrypted_b64}")
    # initialize mongo
    app.logger.debug(f"{callback.__name__}: Initializing mongo")
    db = mongo_handler.get_client('auth')
    collection = mongo_handler.get_collection(db, 'user_data')
    query = {'email': email}
    user_record = mongo_handler.fetch_one(collection, query)
    app.logger.debug(f"{callback.__name__}: User record: {user_record}")
    if not user_record:
        # insert user record in mongo
        app.logger.debug(f"{callback.__name__}: User record not found in mongo")
        user_record = {
            'email': email,
            'jwt-id': jwt_id,
            'refresh-id': refresh_id,
            'credentials_encrypted': credentials_encrypted_b64,
            'registered-date': datetime.datetime.now(datetime.timezone.utc),
            'last-update': datetime.datetime.now(datetime.timezone.utc),
            'scopes': scope,
        }
        post_id = mongo_handler.insert_one(collection, user_record)
        if not post_id:
            app.logger.debug(f"{callback.__name__}: Error inserting user record in mongo")
            return Response("Error inserting user record in mongo", 500)
        else:
            app.logger.debug(f"{callback.__name__}: User record inserted in mongo")
    # update user record in mongo
    else:
        app.logger.debug(f"{callback.__name__}: User record found in mongo")
        user_record['jwt-id'] = jwt_id
        user_record['refresh-id'] = refresh_id
        user_record['credentials_encrypted'] = credentials_encrypted_b64
        user_record['last-update'] = datetime.datetime.now(datetime.timezone.utc)
        user_record['scopes'] = scope
        post_id = mongo_handler.update_one(collection, query, user_record)
        app.logger.debug(f"{callback.__name__}: User record updated in mongo")


    app.logger.debug(f"{callback.__name__}: User record: {user_record}")
    app.logger.debug(f"{callback.__name__}: Post ID: {post_id}")
    app.logger.debug(f"{callback.__name__}: Unique ID: {unique_id}")
    response = make_response(redirect("http://127.0.0.1:8080"+request_url))
    response.set_cookie('unique_id',unique_id, httponly=True)
    response.set_cookie('jwt_token', jwt_token, httponly=True)
    response.set_cookie('refresh_token', refresh_token, httponly=True)

    return response

@app.route('/upgrade-scope')
def upgrade_scope():
    """
        Accepts scopes requested and email id of the user.
        Queries mongo to fetch the credential of the user.
        Has the user auhorize the new scopes.
        Encrypts the new credentials and stores in mongo.
        Upgrade scopes in mongo.
    """
    # fetch data
    app.logger.debug(f"{upgrade_scope.__name__}: Inside upgrade scope")
    data = request.args
    scopes_requested = data.get('scopes')
    app.logger.debug(f"{upgrade_scope.__name__}: Scopes requested: {scopes_requested}")
    email = rc.get(request.cookies.get('unique_id'), app.logger).get('email')
    app.logger.debug(f"{upgrade_scope.__name__}: Email: {email}")

    # fetch user record from mongo
    db = mongo_handler.get_client('auth')
    collection = mongo_handler.get_collection(db, 'user_data')
    query = {'email': email}
    user_record = mongo_handler.fetch_one(collection, query)
    app.logger.debug(f"{upgrade_scope.__name__}: User record: {user_record}")
    if not user_record:
        return Response("User not found", 404)
    # Authorize new scopes
    cred_gen = CredsGenerator(scopes_requested)
    cred_gen.authorize(request.cookies.get('unique_id'))
    data = {'state': cred_gen.state, 'request_url': request.args.get('next'), 'scopes': scopes_requested}   
    rc.set(request.cookies.get('unique_id'), data, app.logger)
    app.logger.debug(f"{upgrade_scope.__name__}: rc data set: {data}")
    authorization_url = cred_gen.authorization_url
    app.logger.debug(f"{upgrade_scope.__name__}: Requesting authorization for new scopes")
    return redirect(authorization_url)

@app.route('/refresh-token', methods=['POST'])
def refresh():
    # not checking for unique_id since it only contains optional data
    # if data is unavaialble in redis, check mongo for data
    app.logger.debug(f"{refresh.__name__}: Request cookies: {request.cookies}")
    refresh_token = request.cookies.get('refresh_token')
    jwt_token = request.cookies.get('jwt_token')
    unique_id = request.cookies.get('unique_id')
    app.logger.debug(f"{refresh.__name__}: Unique ID: {unique_id if unique_id else 'Not Found'}")
    app.logger.debug(f"{refresh.__name__}: Refresh Token: {refresh_token[:10] if refresh_token else 'Not Found'}")
    app.logger.debug(f"{refresh.__name__}: JWT Token: {jwt_token[:10] if jwt_token else 'Not Found'}")
    data = rc.get(unique_id, app.logger) if unique_id else None
    app.logger.debug(f"{refresh.__name__}: Data: {data}")
    email = data.get('email') if data else None
    if not refresh_token or not jwt_token:
        return Response("Invalid request", 401)

    jwt_key = key_wallet.get_pub_key(Keys.JWT_TOKEN)
    refresh_key = key_wallet.get_pub_key(Keys.REFRESH_TOKEN)
    options = {
        "verify_exp": False,
        "verify_iss": False,
        "verify_aud": False,
        "verify_iat": False,
    }
    jwt_id = jwt.decode(jwt_token, jwt_key, algorithms=['RS256'], verify=False, options=options ).get('jti')
    refresh_id = jwt.decode(refresh_token, refresh_key,algorithms=['RS256'], verify=False, options=options).get('jti')
    app.logger.debug(f"{refresh.__name__}: JWT ID: {jwt_id}")
    app.logger.debug(f"{refresh.__name__}: Refresh ID: {refresh_id}")
    
    # check if jwt_id and refresh_id are present in mongo
    db = mongo_handler.get_client('auth') 
    collection = mongo_handler.get_collection(db, 'user_data')
    query = {'jwt-id': jwt_id, 'refresh-id': refresh_id}
    app.logger.debug(f"{refresh.__name__}: Query: {query}")
    user_record = mongo_handler.fetch_one(collection, query)
    app.logger.debug(f"{refresh.__name__}: User record: {user_record}") 
    if not user_record:
        # invalid jwt and refresh token combination
        # or not matching emails
        # can possibly log this refresh token and username in security logs for further investigation
        # throw error
        return Response("Invalid JWT and Refresh Token combination", 401)

    # create new jwt token and refresh token
    jwt_id_new = str(uuid.uuid4())
    app.logger.debug(f"{refresh.__name__}: Creating new jwt id: {jwt_id}")
    refresh_id_new = str(uuid.uuid4())
    app.logger.debug(f"{refresh.__name__}: Creating new refresh id: {refresh_id}")
    app.logger.debug(f"{refresh.__name__}: Creating new jwt and refresh tokens")
    jwt_pvt_key, jwt_key_password = key_wallet.get_pvt_key(Keys.JWT_TOKEN)
    refresh_pvt_key, refresh_key_password = key_wallet.get_pvt_key(Keys.REFRESH_TOKEN)
    jwt_token, refresh_token = JWTHandler.create_tokens(email if email else user_record['email'], jwt_id_new, jwt_pvt_key, jwt_key_password, refresh_id_new, refresh_pvt_key, refresh_key_password)
    app.logger.debug(f"{refresh.__name__}: JWT Token: {jwt_token[:10] if jwt_token else 'Not Found'}")
    app.logger.debug(f"{refresh.__name__}: Refresh Token: {refresh_token[:10] if refresh_token else 'Not Found'}")
    # update jwt-id and refresh-id in mongo
    app.logger.debug(f"{refresh.__name__}: Updating user record in mongo")
    user_record['jwt-id'] = jwt_id_new
    user_record['refresh-id'] = refresh_id_new
    user_record['last-update'] = datetime.datetime.now(datetime.timezone.utc)
    # update last-update in mongo
    post_id = mongo_handler.update_one(collection, query, user_record)
    app.logger.debug(f"{refresh.__name__}: Post ID: {post_id}")
    if not post_id:
        app.logger.debug(f"{refresh.__name__}: Error updating user record in mongo")
        return Response("Error updating user record in mongo, try again later", 500)

    app.logger.debug(f"{refresh.__name__}: User record updated in mongo")
    # update jwt_token and refresh_token in cookies
    response = make_response(redirect(request.url))
    response.set_cookie('jwt_token', jwt_token, httponly=True)
    response.set_cookie('refresh_token', refresh_token, httponly=True)
    # return response
    return response, 200

@app.route('/logout', methods=['POST'])
def logout():
    unique_id = request.cookies.get('unique_id')
    refresh_token = request.cookies.get('refresh_token')
    jwt_token = request.cookies.get('jwt_token')
    app.logger.debug(f"{logout.__name__}: Unique ID: {unique_id}")
    app.logger.debug(f"{logout.__name__}: Refresh Token: {refresh_token[:10] if refresh_token else 'Not Found'}")
    app.logger.debug(f"{logout.__name__}: JWT Token: {jwt_token[:10] if jwt_token else 'Not Found'}")
    
    if refresh_token or not jwt_token:
        app.logger.debug(f"{logout.__name__}: Invalid request")
        return Response("Invalid request", 401)
    
    # delete unique_id from redis
    app.logger.debug(f"{logout.__name__}: Deleting unique_id from redis")
    if unique_id: rc.delete(unique_id)
    # delete jwt_token and refresh_token from cookies
    response = make_response(redirect(url_for('login')))
    if unique_id: response.set_cookie('unique_id', '', expires=0)
    app.logger.debug(f"{logout.__name__}: Deleting jwt_token and refresh_token from cookies")
    app.logger.debug(f"{logout.__name__}: Response: {response}")
    app.logger.debug(f"{logout.__name__}: Response cookies: {response.cookies}")
    response.set_cookie('jwt_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)

    # get jwt_id and refresh_id from jwt_token and refresh_token
    app.logger.debug(f"{logout.__name__}: Getting jwt_id and refresh_id from jwt_token and refresh_token")
    jwt_key = key_wallet.get_pub_key(Keys.JWT_TOKEN)
    refresh_key = key_wallet.get_pub_key(Keys.REFRESH_TOKEN)
    
    jwt_id = jwt.decode(jwt_token, jwt_key, algorithms=['RS256'], verify=False).get('jti')
    app.logger.debug(f"{logout.__name__}: JWT ID: {jwt_id[:10]}")
    refresh_id = jwt.decode(refresh_token, refresh_key,algorithms=['RS256'], verify=False).get('jti')
    app.logger.debug(f"{logout.__name__}: Refresh ID: {refresh_id}")

    # Remove jwt_id and refresh_id from MongoDB
    db = mongo_handler.get_client('auth')
    collection = mongo_handler.get_collection(db, 'user_data')
    query = {'jwt-id': jwt_id, 'refresh-id': refresh_id}
    app.logger.debug(f"{logout.__name__}: Deleting jwt_id and refresh_id from mongo")
    app.logger.debug(f"{logout.__name__}: Query: {query}")
    update_query = {'$unset': {'jwt-id': '', 'refresh-id': ''}}
    post_id = mongo_handler.update_one(collection, query, update_query)
    app.logger.debug(f"{logout.__name__}: Post ID: {post_id}")
    if not post_id:
        app.logger.debug(f"{logout.__name__}: Error updating user record in mongo")
        app.logger.debug(f"Error updating user record in mongo: {post_id}")
    app.logger.debug(f"{logout.__name__}: Logged out")
    return Response("Logged out", 200)



if __name__ == '__main__':
    app.run(host="0.0.0.0", port = os.getenv('AUTH_PORT'))