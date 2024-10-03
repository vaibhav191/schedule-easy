import logging
import os
import sys
from time import sleep
import traceback
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
'''
Notification consumer will check for messages in notificationQ, once a message is found:
    1. Take message -> fid, email
    2. get fid object, convert to temp file (if needed)
    3. email the file to user, delete the temp file (if created)
'''

notification_email_id = os.getenv('NOTIFICATION_EMAIL_ID')
notification_email_password = os.getenv('NOTIFICATION_EMAIL_PASSWORD')

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
status = False
try_count = 0

while not status and try_count < 10:
    try:
        rabbitmq = RabbitMQ()
        logging.debug(f"RabbitMQ connection established.")
        status = True
    except pika.exceptions.AMQPConnectionError:
        logging.debug(f"RabbitMQ connection failed. Retrying...")
        status = False
        try_count += 1
        sleep(5)
    except Exception as e:
        logging.debug(f"Error: {str(e)}")
        logging.debug(f"{traceback.format_exc()}")
        rabbitmq.close()
        sys.exit(1)
if not status:
    logging.debug(f"RabbitMQ connection failed. Exiting...")
    sys.exit(1)


'''
consumer ->
    1. get file from mongo
    2. create temp file.xlsx
    3. email tempfile.xlsx:W
'''
def consumer(ch, method, properties, body):
    if type(body) == bytes:
        body = body.decode('utf-8')
    body = json.loads(body)
    fid = ObjectId(body['fid'])
    email = body['email']
    # init mongo client
    client = MongoClient("mongodb://localhost:27017")
    event_req_coll = client['event_automation']
    if not client:
        return Response("Mongo client not found", 500)
    fs = gridfs.GridFS(event_req_coll) 
    # To do
        # get dict from mongo instead of file
        # convert dict to dataframe and save as excel

    # get file from mongo
    obj = fs.get(fid)
    # create temp file
    # df = pd.read_excel(obj)
    # df.to_excel('Results_'+str(uuid4)+'.xlsx')
    # email file
    mailer(notification_email_id, notification_email_password, email, obj)
    # delete temp file
    fs.delete(fid)

def mailer(username, password, email_receiver, file_obj):
    subject = "Event Scheduling Results" 
    msg = MIMEMultipart()
    msg['From'] = username 
    msg['To'] = email_receiver
    msg['Subject'] = subject

    body = ""
    msg.attach(MIMEText(body, 'plain'))

    part = MIMEBase('application', 'octet-stream')
    part.set_payload(file_obj.read())
    encoders.encode_base64(part)
    part.add_header('content-disposition', "attachment; filename= "+ "Event_results.xlsx")

    msg.attach(part)
    text = msg.as_string()

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(username, password)

    server.sendmail(username, email_receiver, text)
    server.quit()


if __name__ == '__main__':
    rabbitmq.consume('notificationQ', consumer)