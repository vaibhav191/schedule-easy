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
'''
import os, base64, json
from typing import List, Dict
from flask import redirect, request, url_for
from google.oauth2.credentials import Credentials
import google_auth_oauthlib.flow
from handlers.kms_handler import KMSHandler

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
