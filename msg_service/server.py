from flask import Flask, Response, request
import pika
import json
'''
Let's have a publisher and consumer
2 queues = EventQ and NotificationQ
Publisher will take queue name, and message,
2 consumers, one for eventQ and another for NotificationQ
eventQ consumer will call event_service and returns 200 and removes from eventQ
    event_service will on its own call gcp_service and once compelted use publisher to post to notificationQ
    we do not want to wait for event_service to complete before removing from eventQ as any error in event_service or gcp_service will cause
        duplicate events
notificationQ consumer will call notification_service
'''

server = Flask(__name__)

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


@server.route('/publish_event', methods = ['POST'])
def event_publisher():
    if not request:
        return Response("No request found", status = 500)
    payload = request.get_json()
    fid = payload['fid']
    jwt = payload['jwt']
    email = payload['email']
    rabbitmq = RabbitMQ()
    rabbitmq.publish(queue_name = "eventQ", message = json.dumps({'fid':fid, 'jwt': jwt, 'email': email}))
    rabbitmq.close()
    return Response("Message published successfully", status = 200)

@server.route('/publish_notification', methods=["POST"])
def notification_publisher():
    pass

def notification_consumer():
    pass

if __name__ == '__main__':
    server.run(host = "127.0.0.1", port = 9989)
    