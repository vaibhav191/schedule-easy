from uuid import uuid4
from flask import Flask, make_response, request, Response, redirect, session, render_template, send_file
import jwt
import requests
from pymongo import MongoClient
import os
import gridfs
import json
from gateway_service.handlers.mongo_handler import MongoDBHandler
from handlers.jwt_handler import JWTHandler
from handlers.key_handler import KeyHandler
from handlers.redis_handler import RedisHandler
from flask import url_for
from flask import redirect
from flask import request
from flask import send_file
from flask import session
from flask import render_template
from models.keys import Keys
from models.key_types import KeyTypes

rc = RedisHandler()
key_wallet = KeyHandler()
mongo_handler = MongoDBHandler()

server = Flask(__name__, template_folder='templates', static_folder='static')

# we need redis,mongo, keywallet, jwt_handler, gridfs, requests
auth_service_address = os.getenv('AUTH_SERVICE_ADDRESS', 'auth_service')
auth_service_port = os.getenv('AUTH_SERVICE_PORT', '5000')
auth_service_url = f"http://{auth_service_address}:{auth_service_port}"
login_endpoint = "/login"
refresh_endpoint = "/refresh-token"
logout_endpoint = "/logout"

msg_service_address = os.getenv('MSG_SERVICE_ADDRESS', 'msg_service')
msg_service_port = os.getenv('MSG_SERVICE_PORT', '9989')
msg_service_url = f"http://{msg_service_address}:{msg_service_port}"
publish_event_endpoint = "/publish_event"

def validate_tokens(f):
    def wrapper(*args, **kwargs):
        print("Validating tokens.")
        # check if session has jwt, refresh token, unique id
        refresh_token = request.cookies.get('refresh_token')
        jwt_token = request.cookies.get('jwt_token')
        unique_id = request.cookies.get('unique_id')
        # Do we need to check for unique_id? since redis is optional storage
        # if we do not have unique_id available just use mongo for data instead
        
        if not refresh_token or not jwt_token:
            return redirect(auth_url + login_endpoint)
        # check if jwt is valid
        print("Checking if jwt is valid.")
        jwt_key = key_wallet.get_pub_key(Keys.JWT_TOKEN)
        jwt_token_valid = JWTHandler.validate_jwt_token(jwt_token, jwt_key)
        print("JWT Valid:", jwt_token_valid)
        print("Unique ID check:", unique_id)
        if not unique_id:
            print("Unique ID not found, setting.")
            email = jwt.decode(jwt_token, jwt_key, algorithms=['RS256'], verify=False)['sub']
            unique_id = str(uuid4())
            rc.set(unique_id, email)
        print("Unique ID:", unique_id)
        if not jwt_token_valid:
            print("JWT token not valid.")
            # if not valid, check if refresh token is valid
            refresh_key = key_wallet.get_pub_key(Keys.REFRESH_TOKEN)
            refresh_token_valid = JWTHandler.validate_jwt_token(refresh_token, refresh_key)
            if not refresh_token_valid:
                print("Refresh token not valid.")
                return redirect(auth_service_url + login_endpoint)
            
            # if refresh token is valid, call refresh token endpoint
            print("Calling refresh token endpoint.")
            response = requests.post(auth_service_url + refresh_endpoint)
            print("Refresh token response:", response)
            if response.status_code != 200:
                return redirect(auth_service_url + login_endpoint)

            new_jwt_token = response.cookies.get('jwt_token')
            new_refresh_token = response.cookies.get('refresh_token')
            response = make_response(redirect(url_for(f.__name__)))
            # set new jwt token and refresh token in cookies
            response.set_cookie('jwt_token', new_jwt_token)
            response.set_cookie('refresh_token', new_refresh_token)
            response.set_cookie('unique_id', unique_id)
            return response
        return f(*args, **kwargs)
    return wrapper

@server.route("/", methods = ["GET"])
def home():
    # when we come to home, show them the home screen
    # send them to main screen if they have valid jwt token, refresh token and unique_id
    if not request.cookies.get('jwt_token') or not request.cookies.get('refresh_token') or not request.cookies.get('unique_id'):
        return render_template("home.html")

@server.route("/main", methods=["GET"])
@validate_tokens
def main():
    unique_id = request.cookies.get('unique_id')
    email = rc.get(unique_id)
    data = [
        {
            'email': email
        }
    ]
    return render_template('main.html', data = data)

@server.route("/download", methods=["GET"])
def download():
    return send_file('static/event_template.xlsx', as_attachment = True)

@server.route("/upload", methods=["POST"])
def upload():
    try:
        # Get the uploaded file from the request
        uploaded_file = request.files.get("file")
        if uploaded_file:
            #uploaded_file.save(os.path.join(os.getcwd(), uploaded_file.filename))
            if not uploaded_file.filename.lower().endswith(('.xlsx', '.xls')):
                return Response("Invalid file type. Only .xlsx and .xls files are allowed.", status=400)
            # take file from request
            # Check file size
            
            # init mongo client
            db = mongo_handler.get_client('event_automation')
            if not db:
                print("Mongo client DB not found")
                return Response("Mongo client DB not found", 500)
            fs = gridfs.GridFS(db) 
            # call mongo service for upload
            fid = fs.put(uploaded_file)
            # send obj to msg_service publisher to eventQ
            response = requests.post(msg_service_url + publish_event_endpoint, json = {'fid': str(fid), 'jwt':session['Authorization'].split(' ')[1], 'email': session['email']})
            if response.status_code != 200:
                print("Error posting to eventQ:",response)
                return Response(f"Error posting to EventQ:{response}", status = 500)
        return Response("Success", status=200)
    except Exception as e:
        print(f"Error: {str(e)}")
        return Response(f"Error: {str(e)}", status=500)   

@server.route("/consume", methods=["POST"])
def consume():
    # call event_service
    pass

@server.route("/login", methods = ["GET"])
def login():
    return redirect(url_for('main'))

if __name__ == "__main__":
    server.secret_key = "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"
    server.run(host="127.0.0.1", port = 8080) 