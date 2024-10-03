import base64
import logging
import sys
from flask import Response
import pandas as pd # type: ignore
from pymongo import MongoClient
from bson.objectid import ObjectId
import gridfs
import json
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from uuid import uuid4
import os
from handlers.kms_handler import KMSHandler
from handlers.mongo_handler import MongoDBHandler
from handlers.rabbitmq_handler import RabbitMQ
# pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
kms = KMSHandler()
mongo_handler = MongoDBHandler()
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

crypto_host = os.getenv('CRYPTO_HOST')
crypto_port = os.getenv('CRYPTO_PORT')
crypto_url = f"http://{crypto_host}:{crypto_port}"
decrypt_endpoint = "/decrypt"

msg_host = os.getenv('MSG_HOST')
msg_port = os.getenv('MSG_PORT')
msg_url = f"http://{msg_host}:{msg_port}"
publish_message_endpoint = "/publish_message"

'''
event consumer will create a request to event_service
'''
def event_consumer(ch, method, properties, body):
    body = json.loads(body)
    logging.debug(f"{event_consumer.__name__}: {body}")
    message_b64 = body['message']
    message_hash_b64 = body['hash']
    message_hash_bytes = base64.b64decode(message_hash_b64)
    # validate the hash of the message_b64
    hash_bytes = kms.generate_hmac(message_b64, kms.eventQ_mac_keyId)
    logging.debug(f"{event_consumer.__name__} message_hash_bytes: {message_hash_bytes}")
    logging.debug(f"{event_consumer.__name__} hash_bytes: {hash_bytes}")
    if hash_bytes != message_hash_bytes:
        logging.debug(f"{event_consumer.__name__}: Hashes do not match.")
        return
    # if valid, decode the b64 message
    message_json = base64.b64decode(message_b64).decode('utf-8') # gives string
    logging.debug(f"{event_consumer.__name__} decoded message json: {message_json}")
    message = json.loads(message_json)
    fid = message['fid']
    email = message['email']
    fid_read = ObjectId(fid)
    # fetch cred using email id from mongo
    client = mongo_handler.get_client('auth')
    collection = mongo_handler.get_collection(client, 'user_data')
    query = {'email': email}
    data = mongo_handler.fetch_one(collection, query)
    if not data:
        logging.debug(f"{event_consumer.__name__}: No data found for email: {email}, data fetched: {data if data else 'Not Found'}, db: {client}, collection: {collection}")
        return
    cred_encrypted_b64 = data['credentials_encrypted']
    # decrypt the cred using auth_service
    data = {
        'key_name': 'OAUTH_CREDENTIALS',
        'ciphertext': cred_encrypted_b64
    }
    response = requests.post(crypto_url + decrypt_endpoint, json = data)
    if response.status_code != 200:
        logging.debug(f"{event_consumer.__name__}: Error decrypting credentials, status code: {response.status_code}, response: {response.content}")
        return
    cred = response.json()
    # init mongo client fetch file from mongo
    db = mongo_handler.get_client('pending_files') 
    fs = gridfs.GridFS(db)
    # get file content from mongo
    obj = fs.get(fid_read)
    logging.debug(f"{event_consumer.__name__}: File fetched from mongo, obj: {obj if obj else 'Not Found'}")
    # convert to dataframe
    df = pd.read_excel(obj, skiprows = 1)
    logging.debug(f"{event_consumer.__name__}: Dataframe created from file, df: {df if df else 'Not Found'}")
    if len(df) == 0:
        logging.debug(f"{event_consumer.__name__}: No data found in file, exiting.")
        return
    # create_event
    df_result = create_events(cred, df)
    df_result.drop(columns = [df.columns[0]], inplace = True)
    logging.debug(f"{event_consumer.__name__}: Events created, df_result: {df_result if df_result else 'Not Found'}")
    # To do - convert dataframe to dict and save in mongo db instead of saving in file
    df_dict = df_result.to_dict()
    logging.debug(f"{event_consumer.__name__}: Dataframe converted to dict, df_dict: {df_dict if df_dict else 'Not Found'}")
    # upload result in mongodb
    db = mongo_handler.get_client('results')
    fs = gridfs.GridFS(db) 
    df_dict_json = json.dumps(df_dict)
    fid_results = fs.put(df_dict_json)
    logging.debug(f"{event_consumer.__name__}: Results uploaded to mongo, fid_results: {fid_results if fid_results is not None else 'Not Found'}")
    # delete file from mongo
    fs.delete(fid_read)
    logging.debug(f"{event_consumer.__name__}: File deleted from mongo, fid_read: {fid_read if fid_read is not None else 'Not Found'}")
    # send a post request to msg_service to put this message in notificationQ
    data = {
        'fid': str(fid_results),
        'email': email
    }
    # publish fileid in notificationQ
    logging.debug(f"{event_consumer.__name__}: Publishing notification, data: {data}")
    publish_notification(data, 'notificationQ') 
    logging.debug(f"{event_consumer.__name__}: Notification published successfully. Exiting.")

def publish_notification(message, queue_name):
    rabbitmq = RabbitMQ()
    rabbitmq.publish(queue_name = queue_name, message = json.dumps(message)) 
    rabbitmq.close()

def create_events(cred, df):
    cred = Credentials.from_authorized_user_info(cred)
    service = build("calendar", "v3", credentials=cred)
    df['Status'] = None
    df['EventId'] = None
    status_index = int(df.columns.get_indexer(['Status'])[0])
    eventid_index = int(df.columns.get_indexer(['EventId'])[0])
    for i,(index, row) in enumerate(df.iterrows()):
        event = {}
        na_or_val = lambda x: None if pd.isna(x) else x
        event['summary'] = na_or_val(row['Subject']) 
        event['description'] = na_or_val(row['Description'])
        event['location'] = na_or_val(row['Location'])
        event['start'] = {'dateTime':str(row["StartDate"])[:10] + "T"+str(row["StartTime"]), "timeZone" : row["TimeZone"]}
        event["end"] = {"dateTime" : str(row["EndDate"])[:10] + "T" + str(row["EndTime"]), "timeZone" : row["TimeZone"]}
        event['reminders'] = {'useDefault':False, 'overrides' : [{"method":'popup', 'minutes':15}]}
        
        
        event = service.events().insert(calendarId='primary', body=event).execute()
        df.iloc[i, eventid_index] = event['id']
        df.iloc[i, status_index] = event['status']
        
    return df

if __name__ == '__main__':
    rabbitmq = RabbitMQ()
    rabbitmq.consume('eventQ', event_consumer)