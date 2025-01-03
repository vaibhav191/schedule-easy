"""
    - Get msg_service up and running and then work on upload endpoint
"""
import base64
from uuid import uuid4
from flask import Flask, jsonify, make_response, request, Response, redirect, session, render_template, send_file
import jwt
import requests
from pymongo import MongoClient
import os
import gridfs
import json
from handlers.mongo_handler import MongoDBHandler
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
import sys
import logging
from models.scopes import Scopes

rc = RedisHandler()
key_wallet = KeyHandler()
mongo_handler = MongoDBHandler()

server = Flask(__name__, template_folder='templates', static_folder='static')
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# we need redis,mongo, keywallet, jwt_handler, gridfs, requests
site_domain = os.getenv('SITE_DOMAIN')
auth_host = os.getenv('AUTH_HOST') 
auth_service_port = os.getenv('AUTH_PORT', '5000')
auth_service_url = f"{site_domain}:{auth_service_port}"
login_endpoint = "/login"
refresh_endpoint = "/refresh-token"
logout_endpoint = "/logout"
upgrade_scope_endpoint = "/upgrade-scope"

msg_service_address = os.getenv('MSG_HOST')
msg_service_port = os.getenv('MSG_PORT')
msg_service_url = f"http://{msg_service_address}:{msg_service_port}"
publish_event_endpoint = '/publish_message'

def validate_tokens(f):
    def wrapper(*args, **kwargs):
        server.logger.debug(f"{validate_tokens.__name__}: Validating tokens.")
        refresh_token = None
        jwt_token = None
        unique_id = None
        # check if its a response from auth service
        server.logger.debug(f"{wrapper.__name__}: Request: {request.host}")
        refresh_token = request.cookies.get('refresh_token')
        server.logger.debug(f"{wrapper.__name__}: Refresh Token: {refresh_token[:10] if refresh_token else 'Not Found'}")
        jwt_token = request.cookies.get('jwt_token')
        server.logger.debug(f"{wrapper.__name__}: JWT Token: {jwt_token[:10] if jwt_token else 'Not Found'}")
        unique_id = request.cookies.get('unique_id')
        server.logger.debug(f"{wrapper.__name__}: Unique ID: {unique_id if unique_id else 'Not Found'}")
        # Do we need to check for unique_id? since redis is optional storage
        # if we do not have unique_id available just use mongo for data instead
        if not refresh_token or not jwt_token:
            return redirect(url_for('login'))
        server.logger.debug(f"{wrapper.__name__}: Unique ID check: {unique_id}")
        if not unique_id:
            server.logger.debug(f"{wrapper.__name__}: Unique ID not found, setting.")
            email = jwt.decode(jwt_token, jwt_key, algorithms=['RS256'], verify=False)['sub']
            unique_id = str(uuid4())
            data = {'email': email}
            rc.set(unique_id, data)
        server.logger.debug(f"{wrapper.__name__}: Unique ID: {unique_id}")
        # check if jwt is valid
        server.logger.debug(f"{wrapper.__name__}: Checking if jwt is valid.")
        jwt_key = key_wallet.get_pub_key(Keys.JWT_TOKEN)
        jwt_token_valid = JWTHandler.validate_jwt_token(jwt_token, jwt_key, server.logger)
        server.logger.debug(f"{wrapper.__name__}: JWT Valid: {jwt_token_valid}")
        if not jwt_token_valid:
            server.logger.debug(f"{wrapper.__name__}: JWT token not valid.")
            # if not valid, check if refresh token is valid
            refresh_key = key_wallet.get_pub_key(Keys.REFRESH_TOKEN)
            refresh_token_valid = JWTHandler.validate_refresh_token(refresh_token, refresh_key, server.logger)
            server.logger.debug(f"{wrapper.__name__}: Refresh token valid?: {refresh_token_valid}")
            if not refresh_token_valid:
                return redirect(url_for('login'))
            # if refresh token is valid, call refresh token endpoint
            server.logger.debug(f"{wrapper.__name__}: Calling refresh token endpoint.")
            server.logger.debug(f"{wrapper.__name__}: calling refresh token endpoint: {auth_service_url + refresh_endpoint}")
            cookies = {'refresh_token': refresh_token, 'unique_id': unique_id, 'jwt_token': jwt_token}
            server.logger.debug(f"{wrapper.__name__}: Using cookies: {cookies}")
            response = requests.post("http://"+auth_host +":"+ auth_service_port + refresh_endpoint, cookies=cookies)
            server.logger.debug(f"{wrapper.__name__}: Response Statuc: {response.status_code}, Refresh content: {response.content}")
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

@server.route("/", methods = ["GET"])
def home():
    server.logger.debug(f"{home.__name__}: Home route.")
    server.logger.debug(f"{home.__name__}: Request host: {request.host}")
    server.logger.debug(f"{home.__name__}: Request cookies: {request.cookies}")
    jwt_token = request.cookies.get('jwt_token')
    refresh_token = request.cookies.get('refresh_token')
    unique_id = request.cookies.get('unique_id')
    server.logger.debug(f"{home.__name__}: JWT Token: {jwt_token if jwt_token else 'Not Found'}")
    server.logger.debug(f"{home.__name__}: Refresh Token: {refresh_token[:10] if refresh_token else 'Not Found'}")
    server.logger.debug(f"{home.__name__}: Unique ID: {unique_id if unique_id else 'Not Found'}")
    # when we come to home, show them the home screen
    # send them to main screen if they have valid jwt token, refresh token and unique_id
    if jwt_token and refresh_token and unique_id:
        server.logger.debug(f"{home.__name__}: Redirecting to main.")
        return redirect(url_for('main'))
    return render_template("home_refined.html", auth_host = site_domain+":", auth_port = auth_service_port)

@server.route("/main", methods=["GET"])
@validate_tokens
def main():
    server.logger.debug(f"{main.__name__}: Main route.")
    unique_id = request.cookies.get('unique_id')
    redis_data = rc.get(unique_id, server.logger)
    server.logger.debug(f"{main.__name__}: Redis data: {redis_data if redis_data else 'Not Found'}")
    server.logger.debug(f"{main.__name__}: unique_id: {unique_id}") 
    return render_template('main_refined.html', email = redis_data['email'], unique_id = unique_id)

@server.route("/download", methods=["GET"])
@validate_tokens
def download():
    return send_file('static/event_template.xlsx', as_attachment = True)

@server.route("/upload", methods=["POST"])
@validate_tokens
def upload():
    # try:
    server.logger.debug(f"{upload.__name__}: Upload route.")
    server.logger.debug(f"{upload.__name__}: Request host: {request.host}")
    # Get the uploaded file from the request
    uploaded_file = request.files.get("file")
    server.logger.debug(f"{upload.__name__}: File: {uploaded_file if uploaded_file else 'Not Found'}")
    if uploaded_file:
        # get email from redis
        unique_id = request.cookies.get('unique_id')
        if not unique_id:
            jwt_token = request.cookies.get('jwt_token')
            email = jwt.decode(jwt_token, key_wallet.get_pub_key(Keys.JWT_TOKEN), algorithms=['RS256'], verify=False)['sub']
        else:
            email = rc.get(unique_id, server.logger)['email']
        server.logger.debug(f"{upload.__name__}: Email: {email}")
        # check if user scope is valid
        db = mongo_handler.get_client('auth')
        collection = mongo_handler.get_collection(db, 'user_data')
        query = {'email': email}
        data = mongo_handler.fetch_one(collection, query)
        server.logger.debug(f"{upload.__name__}: Data user_record: {data}")
        if not data:
            return Response("User not found", status=404)
        scopes = data['scopes']
        if Scopes.FULL_EVENTS.value not in scopes:
            server.logger.debug(f"{upload.__name__}: Calendar Scope not found.")
            # request additional scope
            server.logger.debug(f"{upload.__name__}: Requesting additional scope.")
            return Response("Scope not found.", status=500)
        # uploaded_file.save(os.path.join(os.getcwd(), uploaded_file.filename))
        if not uploaded_file.filename.lower().endswith(('.xlsx', '.xls')):
            return Response("Invalid file type. Only .xlsx and .xls files are allowed.", status=400)
        
        # init mongo client
        db = mongo_handler.get_client('pending_files')
        if db is None:
            server.logger.debug(f"{upload.__name__} Mongo client DB not found")
            return Response("Mongo client DB not found", 500)
        server.logger.debug(f"{upload.__name__} Mongo client DB found, {db}")
        # init gridfs
        fs = gridfs.GridFS(db)
        server.logger.debug(f"{upload.__name__} GridFS: {fs if fs is not None else 'Not Found'}") 
        # insert into mongo
        fid = fs.put(uploaded_file)
        server.logger.debug(f"{upload.__name__} File ID: {fid if fid is not None else 'Not Found'}")
        # generate message for eventQ
        message = {
            'fid': str(fid),
            'email': email,
            'unique_id': unique_id
        }
        server.logger.debug(f"{upload.__name__} Message: {message}")
        message_json = json.dumps(message)
        message_bytes = message_json.encode('utf-8')
        message_b64 = base64.b64encode(message_bytes).decode('utf-8')
        # send obj to msg_service publisher to eventQ
        # get rest of cookies to pass
        jwt_token = request.cookies.get('jwt_token')
        refresh_token = request.cookies.get('refresh_token')
        cookies = {'jwt_token': jwt_token, 'refresh_token': refresh_token, 'unique_id': unique_id}

        server.logger.debug(f"{upload.__name__} Posting to EventQ, url = {msg_service_url + publish_event_endpoint}")
        response = requests.post(msg_service_url + publish_event_endpoint,
                                  json = {'message': message_b64, 'queue_name': 'eventQ'},
                                  cookies=cookies)
        if response.status_code != 200:
            server.logger.debug(f"{upload.__name__} Error posting to EventQ:{response}")
            return Response(f"Error posting to EventQ:{response}", status = 500)
        else :
            server.logger.debug(f"{upload.__name__} Success posting to EventQ. {response.status_code}, {response.content}")
    
    # publish SSE
    publish_update(unique_id, 'Uploaded')

    server.logger.debug(f"{upload.__name__} Success, exiting.")
    # send unique_id as json response
    return jsonify({"message": "Success", "unique_id": unique_id}), 200

@server.route("/logout", methods=["GET"])
def logout():
    server.logger.debug(f"{logout.__name__}: Logout route.")
    # remove jwt token, refresh token, unique_id
    response = make_response(redirect(url_for('home')))
    response.set_cookie('jwt_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    response.set_cookie('unique_id', '', expires=0)
    return response

@server.route("/login", methods = ["GET"])
def login():
    server.logger.debug(f"{login.__name__}: Login route.")
    server.logger.debug(f"{login.__name__}: Request host: {request.host}")
    server.logger.debug(f"{login.__name__}: Request cookies: {request.cookies}")
    # check for existing jwt token and refresh token validity
    jwt_token = request.cookies.get('jwt_token')
    refresh_token = request.cookies.get('refresh_token')
    unique_id = request.cookies.get('unique_id')
    server.logger.debug(f"{login.__name__}: JWT Token: {jwt_token[:10] if jwt_token else 'Not Found'}")
    server.logger.debug(f"{login.__name__}: Refresh Token: {refresh_token[:10] if refresh_token else 'Not Found'}")
    server.logger.debug(f"{login.__name__}: Unique ID: {unique_id if unique_id else 'Not Found'}")
    jwt_key = key_wallet.get_pub_key(Keys.JWT_TOKEN)
    refresh_key = key_wallet.get_pub_key(Keys.REFRESH_TOKEN)
    if jwt_token and refresh_token:
        jwt_token_valid = JWTHandler.validate_jwt_token(jwt_token, jwt_key, server.logger)
        refresh_token_valid = JWTHandler.validate_refresh_token(refresh_token, refresh_key, server.logger)
        if jwt_token_valid and refresh_token_valid:
            server.logger.debug(f"{login.__name__}: Login not required, tokens are valid. Redirecting to main.")
            return redirect(url_for('main'))
    server.logger.debug(f"{login.__name__}: Redirecting to auth service.")
    return redirect(site_domain+":" + login_endpoint + "?next=/main")

# Server sent events
@server.route("/stream/<unique_id>", methods=["GET"])
def stream(unique_id):
    server.logger.debug(f"{stream.__name__}: SSE route.")
    def generate():
        server.logger.debug(f"{generate.__name__}: Generating SSE.")
        pubsub = rc.get_client().pubsub()
        pubsub.subscribe(unique_id)
        for message in pubsub.listen():
            if message['type'] == 'message':
                server.logger.debug(f"{generate.__name__}: Subscription message: {message}")
                yield f"data: {message['data']}\n\n"
            else:
                server.logger.debug(f"{generate.__name__}: Subscription message type: {message['type']} ; message: {message}")
    return Response(generate(), mimetype='text/event-stream')

def publish_update(unique_id, message):
    server.logger.debug(f"{publish_update.__name__}: Publishing update: {message}")
    rc.get_client().publish(unique_id, message)

if __name__ == "__main__":
    server.secret_key = os.getenv('SESSION_SECRET')
    server.run(host="0.0.0.0", port = os.getenv('GATEWAY_PORT'), debug = True)