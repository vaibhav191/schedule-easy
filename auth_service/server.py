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
    -> fetch refresh token from the credential and store in the Mongo.
    -> leverage token to generate  and send JWT token and a refresh token for the user.
    -> Send user back to request url.

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
from datetime import datetime, timedelta
from uuid import uuid4
import hashlib
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import json
import os
from flask import Flask,redirect, request, Response, session, jsonify
from enum import Enum
import requests
import pickle
from file_reader import reader
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Scopes(Enum):
    READ_PROFILE = "https://www.googleapis.com/auth/userinfo.profile"
    READ_EMAIL = "https://www.googleapis.com/auth/userinfo.email"
    FULL_CALENDAR = "https://www.googleapis.com/auth/calendar"
    FULL_EVENTS = "https://www.googleapis.com/auth/calendar.events"

server = Flask(__name__)

# To Do:
# Work on reducing scope: Try and remove READ_PROFILE, we only need email address.
@server.route("/login", methods=["GET"])
def login():
    SCOPES=["openid", Scopes['FULL_EVENTS'].value, Scopes['READ_EMAIL'].value, Scopes['READ_PROFILE'].value ] 
    flow = InstalledAppFlow.from_client_secrets_file("../credentials.json", SCOPES)
    try:
        creds = flow.run_local_server(port = 0)
    except Exception as e:
        return Response("Fail", 501)
    # create jwt, it contains id, cred, expiry, and time issued at
    uid = str(uuid4())
    create_jwt_resp = requests.get('http://127.0.0.1:5000/create-jwt', json = {'uid': uid, 'cred': creds.to_json()})
    # jwt = create_jwt(uid, creds.to_json())
    jwt = create_jwt_resp.text.strip()
    #obtain the email
    resp = requests.get("http://localhost:8000/get_email", headers = {'Authorization': 'Bearer ' + jwt})
    user_email = resp.headers['email']
    session['email'] = user_email
    session['Authorization'] = "Bearer "+ str(jwt)
    session['uid'] = uid
    return redirect("http://127.0.0.1:8080/main") 

@server.route('/create-jwt', methods = ["GET"])
def create_jwt(): 
    payload = request.get_json()
    try:
        passphrase = reader('passphrase', 'r', True)
    except Exception as err:
        return err
    uid = payload['uid']
    cred = payload['cred']
    message = {
                "id" : uid,
                "cred" : cred,
                "issue-time": str(datetime.utcnow()),
                "expiry": str(datetime.utcnow() + timedelta(hours = 1))
            }
    # create JWT
    try:
        jwt_encoded = encode_jwt(message, passphrase, "HS256")
    except Exception as e:
        return 'exception encoding', e
    session['Authorization'] = 'Bearer ' + str(jwt_encoded)
    return jwt_encoded  

@server.route('/refresh-jwt', methods = ['GET'])
def refresh_jwt():
    pass

def encode_jwt(message, private_key, algorithm):
    return jwt.encode(message, private_key, algorithm)

'''
! Decode and Validate function needs to be implemented by each microservice themselves.
'''
@server.route('/decode-jwt', methods=['GET'])
def decode_jwt():
    payload = request.get_json()
    encoded_jwt = payload['encoded_jwt']
    passphrase = reader('passphrase', 'r', True)
    try:
        decoded = jwt.decode(encoded_jwt, passphrase, algorithms = ["HS256"])
        payload = {
            'id': decoded['id'],
            'cred': json.loads(decoded['cred']),
            'issue-time': decoded['issue-time'],
            'expiry' : decoded['expiry']
        }
        return payload
    except Exception as e:
        print(e)
        return e

# validate JWT
@server.route('/validate', methods = ["GET"])
def validate():
    try:
        email = session.get('email', None)
        jwt = session.get('Authorization').split(' ')[1]
        resp_decode_jwt = requests.get("http://127.0.0.1:5000/decode-jwt", json = {'encoded_jwt':jwt})
        resp_decode_jwt_dic = json.loads(resp_decode_jwt.text)
        exp = resp_decode_jwt_dic['expiry']
        # exp = decode_jwt(jwt)['expiry']
        parsed_exp = datetime.strptime(exp, "%Y-%m-%d %H:%M:%S.%f")
        if parsed_exp < datetime.utcnow():
            return Response("Session expired", 401)
    except Exception as e:
        print(e)
        return Response("Unauthorized", 401)

    return Response("success: " + str(email), 200)


# implement a return public key function
@server.route('/pub-key', methods = ['GET'])
def get_public_key():
    pass

'''
Uses cred to make a GCP call obtaining user's email id
'''
@server.route('/get_email', methods = ["GET"])
def get_email():
    # check if request received
    if not request:
        return "No request found", 500
    # check if field cred present in the request
    try:
        encoded_jwt = request.headers['Authorization'].split(' ')[1]
        decoded_jwt_resp = requests.get("http://127.0.0.1:5000/decode-jwt",json = {"encoded_jwt":encoded_jwt})
        print("DECODED_JWT_RESP", decoded_jwt_resp)
        decoded_jwt = json.loads(decoded_jwt_resp.text)
        cred = decoded_jwt['cred']
    except KeyError as e:
        return "cred not found in the request", 500
    try:
        cred = Credentials.from_authorized_user_info(cred)
    except Exception as err:
        print("Exception converting cred json to Credentials")
        return err, 500
    # call gcp for email address
    try:
        print('service and result')
        service = build("people", "v1", credentials = cred)
        result = service.people().get(resourceName='people/me', personFields="emailAddresses").execute()
    except Exception as err:
        print("exception making API call")
        return err, 500
    # try to fetch the primary email from the results
    try:
        print("RESULTS:",result)
        for email_address in result['emailAddresses']:
            if email_address['metadata']['primary'] == True:
                email = email_address['value']
        print('Email: ', email)
    except KeyError as e:
        return str(err), 500

    if email:
        return Response( status = 200, headers = {'email': email})
    return "err in getting email", 500



if __name__ == "__main__":
    creds = json.loads(reader("../credentials.json", "r", False))
    server.secret_key = "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",
    server.run(host="127.0.0.1", port = 5000) 
