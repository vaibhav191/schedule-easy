import base64
import io
import logging
import os
import sys
from time import sleep
import traceback
from typing import Dict
from uuid import uuid4
from flask import Response
import pika # type: ignore
from pymongo import MongoClient
from bson.objectid import ObjectId
import gridfs
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from handlers.rabbitmq_handler import RabbitMQ
import smtplib
import pickle
from handlers.mongo_handler import MongoDBHandler
from handlers.kms_handler import KMSHandler
from handlers.redis_handler import RedisHandler
import pandas as pd # type: ignore
'''
Notification consumer will check for messages in notificationQ, once a message is found:
    1. Take message -> fid, email
    2. get fid object, convert to temp file (if needed)
    3. email the file to user, delete the temp file (if created)
'''

notification_email_id = os.getenv('NOTIFICATION_EMAIL_ID')
notification_email_password = os.getenv('NOTIFICATION_EMAIL_PASSWORD')
rc = RedisHandler()

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

status = False
rabbitmq_conn_tries = 0
while not status and rabbitmq_conn_tries < 10:
    try:
        rabbitmq = RabbitMQ()
        logging.debug(f"RabbitMQ connection established.")
        status = True
    except pika.exceptions.AMQPConnectionError:
        logging.debug(f"RabbitMQ connection failed. Retrying...")
        status = False
        rabbitmq_conn_tries += 1
        sleep(5)
    except Exception as e:
        logging.debug(f"Error: {str(e)}")
        logging.debug(f"{traceback.format_exc()}")
        rabbitmq.close()
        sys.exit(1)
if not status:
    logging.debug(f"RabbitMQ connection failed. Exiting...")
    sys.exit(1)

mongo_handler = MongoDBHandler()
kms = KMSHandler()

'''
consumer ->
    1. get file from mongo
    2. create temp file.xlsx
    3. email tempfile.xlsx:W
'''
def consumer(ch, method, properties, body):
    logging.debug(f"{consumer.__name__} called.")
    body: Dict = json.loads(body)
    logging.debug(f"{consumer.__name__}body: {body if body is not None else 'None'}")
    message_b64 = body.get('message')
    message_hash_b64 = body.get('hash')
    message_hash_bytes = base64.b64decode(message_hash_b64)
    # validate the hash of the message_b64
    logging.debug(f"{consumer.__name__} requesting hash generation from kms.")
    hash_bytes = kms.generate_hmac(message_b64, kms.notificationQ_mac_keyId)
    if hash_bytes != message_hash_bytes:
        logging.debug(f"{consumer.__name__} Hashes do not match.")
        return
    logging.debug(f"{consumer.__name__} Hashes match.")
    message_json = base64.b64decode(message_b64).decode('utf-8') # gives string
    logging.debug(f"{consumer.__name__} decoded message json: {message_json if message_json is not None else 'None'}")
    message = json.loads(message_json)
    fid = ObjectId(message['fid'])
    logging.debug(f"{consumer.__name__} fid: {fid if fid is not None else 'None'}")
    email_receiver = message['email']
    logging.debug(f"{consumer.__name__} email_receiver: {email_receiver if email_receiver is not None else 'None'}")
    unique_id = message['unique_id']
    logging.debug(f"{consumer.__name__} unique_id: {unique_id if unique_id is not None else 'None'}")
    # init mongo client
    logging.debug(f"{consumer.__name__} requesting file from mongo.")
    db = mongo_handler.get_client('results')
    fs = gridfs.GridFS(db)
    file_obj = fs.get(fid)
    logging.debug(f"{consumer.__name__} file_obj: {file_obj if file_obj is not None else 'None'}")
    if not file_obj:
        logging.debug(f"{consumer.__name__} File not found in mongo")
        return 
    df_dict_pickle = file_obj.read()
    logging.debug(f"{consumer.__name__} df_dict_pickle: {df_dict_pickle if df_dict_pickle is not None else 'None'}")
    df_dict: dict = pickle.loads(df_dict_pickle)
    logging.debug(f"{consumer.__name__} df_dict: {df_dict if df_dict is not None else 'None'}")
    df = pd.DataFrame.from_dict(df_dict)
    
    # delete the file from mongo
    fs.delete(fid)
    mailer(notification_email_id, notification_email_password, email_receiver, df)

    #! notification sent successfully, send SSE
    publish_update(unique_id, "Mailed")

def export_to_excel(df):
    logging.debug(f"{export_to_excel.__name__} called.")
    with io.BytesIO() as buffer:
        with pd.ExcelWriter(buffer) as writer:
            df.to_excel(writer)
        return buffer.getvalue()

def mailer(username, password, email_receiver, df):
    logging.debug(f"{mailer.__name__} called.")
    
    subject = "Event Scheduling Results" 
    msg = MIMEMultipart()
    msg['From'] = username 
    msg['To'] = email_receiver
    msg['Subject'] = subject

    body = ""
    msg.attach(MIMEText(body, 'plain'))
    logging.debug(f"{mailer.__name__} body attached to email.")
    part = MIMEBase('application', 'octet-stream')
    logging.debug(f"{mailer.__name__} attempting to attach file.")
    part.set_payload(export_to_excel(df))
    encoders.encode_base64(part)
    part.add_header('content-disposition', "attachment; filename= "+ "Event_results.xlsx")

    msg.attach(part)
    text = msg.as_string()
    logging.debug(f"{mailer.__name__} email prepared.")
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    logging.debug(f"{mailer.__name__} attempting to login.")
    server.login(username, password)
    logging.debug(f"{mailer.__name__} attempting to send email.")
    server.sendmail(username, email_receiver, text)
    logging.debug(f"{mailer.__name__} email sent.")
    server.quit()
    logging.debug(f"{mailer.__name__} server connection closed.")

def publish_update(unique_id, message):
    logging.debug(f"{publish_update.__name__}: Publishing update: {message}")
    rc.get_client().publish(unique_id, message)

if __name__ == '__main__':
    rabbitmq.consume('notificationQ', consumer)
