from uuid import uuid4
from flask import Response
import pika
from pymongo import MongoClient
from bson.objectid import ObjectId
import gridfs
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import smtplib
'''
Notification consumer will check for messages in notificationQ, once a message is found:
    1. Take message -> fid, email
    2. get fid object, convert to temp file (if needed)
    3. email the file to user, delete the temp file (if created)
'''
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
    # get file from mongo
    obj = fs.get(fid)
    # create temp file
    # df = pd.read_excel(obj)
    # df.to_excel('Results_'+str(uuid4)+'.xlsx')
    # email file
    mailer('eventautomation.do.not.reply@gmail.com', 'nnsornbudehheehz', email, obj)
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
    rabbitmq = RabbitMQ()
    rabbitmq.consume('notificationQ', consumer)