from flask import Response
import pika
import pandas as pd
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
class RabbitMQ:
    def __init__(self):
        self.user = 'guest'
        self.password = 'guest'
        self.host = 'localhost'
        self.port = 5672
        self.connection = None
        self.channel = None
        self.properties = pika.BasicProperties(delivery_mode = 2)
        self.connect()
        
    def connect(self):
        credentials = pika.PlainCredentials(self.user, self.password)
        parameters = pika.ConnectionParameters(host = self.host, port = self.port, credentials = credentials)
        self.connection = pika.BlockingConnection(parameters)
        self.channel = self.connection.channel()
    
    def close(self):
        if self.connection and not self.connection.is_closed:
            self.connection.close()
    def consume(self, queue_name, callback):
        if not self.channel:
            raise Exception("Connection is not established.")
        self.channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
        self.channel.start_consuming()
    def publish(self, queue_name, message):
        if not self.channel:
            raise Exception("Connection is not established")
        self.channel.queue_declare(queue = queue_name, durable = True)
        self.channel.basic_publish(exchange = "", routing_key = queue_name, body = message, properties = self.properties) 
'''
event consumer will create a request to event_service
'''
def event_consumer(ch, method, properties, body):
    if type(body) == bytes:
        body = body.decode('utf-8')
    body = json.loads(body)
    fid_read = ObjectId(body['fid'])
    jwt_encoded = body['jwt']
    email = body['email']
    decoded_jwt_response = requests.get("http://127.0.0.1:5000/decode-jwt", json = {'encoded_jwt': jwt_encoded})
    decoded_jwt = json.loads(decoded_jwt_response.text)
    cred = decoded_jwt['cred']
    # init mongo client
    client = MongoClient("mongodb://localhost:27017")
    event_req_coll = client['event_automation']
    if not client:
        return Response("Mongo client not found", 500)
    fs = gridfs.GridFS(event_req_coll) 
    # get file content from mongo
    obj = fs.get(fid_read)
    # convert to dataframe
    df = pd.read_excel(obj, skiprows = 1)
    # create_event
    df_result = create_events(cred, df)
    df_result.drop(columns = [df.columns[0]], inplace = True)
    file_name = "Event_results_" + str(uuid4()) + '.xlsx'
    
    # To do - convert dataframe to dict and save in mongo db instead of saving in file
    
    df_result.to_excel(file_name)
    # upload result in mongodb
    client = MongoClient("mongodb://localhost:27017")
    event_req_coll = client['event_automation']
    if not client:
        return Response("Mongo client not found", 500)
    fs = gridfs.GridFS(event_req_coll) 
    # delete temp file created
    file_path = os.path.join(os.getcwd(), file_name)
    with open(file_path, "rb") as f:
        file_content = f.read()
    fid_write = fs.put(file_content)
    if os.path.exists(file_path):
        os.remove(file_path)
        
    # delete file from mongo
    fs.delete(fid_read)
    
    # publish fileid in notificationQ
    publish_notification(email, str(fid_write))
    

def publish_notification(email, fid):
    rabbitmq = RabbitMQ()
    rabbitmq.publish(queue_name = "notificationQ", message = json.dumps({'fid':fid, 'email': email})) 
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