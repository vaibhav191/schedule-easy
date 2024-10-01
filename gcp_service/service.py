from googleapiclient.discovery import build
from flask import Flask,redirect, request, Response, session
from pickle import loads
from google.oauth2.credentials import Credentials
import requests
import json
server = Flask(__name__)


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
        
        decoded_jwt = json.loads(decoded_jwt_resp.text)
        cred = decoded_jwt['cred']
    except KeyError as e:
        return "cred not found in the request", 500
    try:
        cred = Credentials.from_authorized_user_info(cred)
    except Exception as err:
        
        return err, 500
    # call gcp for email address
    try:
        
        service = build("people", "v1", credentials = cred)
        result = service.people().get(resourceName='people/me', personFields="emailAddresses").execute()
    except Exception as err:
        
        return err, 500
    # try to fetch the primary email from the results
    try:
        
        for email_address in result['emailAddresses']:
            if email_address['metadata']['primary'] == True:
                email = email_address['value']
        
    except KeyError as e:
        return str(err), 500

    if email:
        return Response( status = 200, headers = {'email': email})
    return "err in getting email", 500


def make_calendar_event():
    pass

def delete_calendar_event():
    pass

if __name__ == '__main__':
    server.run(host = "127.0.0.1", port = 8000)
