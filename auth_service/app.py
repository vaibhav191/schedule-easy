'''
To Do:
1. Move get-email to auth_service # Login won't work if google fails to respond to
    request for get-email
2. Remove gcp_service
'''

# we will continue to use crypto service since encrypting and decrypting data with AWS KMS alone can be very costly and time consuming
# due to the number of requests and network latency.
import os
from flask import Flask, redirect, request, Response, url_for, make_response
import uuid
from models.scopes import Scopes
from handlers.redis_handler import RedisHandler
from handlers.key_handler import KeyHandler
from authenticators.google_authenticator import CredsGenerator
from third_party_services.google_service import GcpService
from dotenv import load_dotenv


load_dotenv()
print("ENVIRONMENT VARIABLES:", os.environ)


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


key_wallet = KeyHandler()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port = os.getenv('AUTH_PORT'))