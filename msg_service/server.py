import base64
import logging
import sys
from flask import Flask, Response, request
import json
from handlers.kms_handler import KMSHandler
from handlers.rabbitmq_handler import RabbitMQ
import os
from handlers.key_handler import KeyHandler
from models.keys import Keys
from handlers.jwt_handler import JWTHandler

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

# import dotenv
# dotenv.load_dotenv('../.env')
kms = KMSHandler()
key_wallet = KeyHandler()
server = Flask(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def validate_tokens(f):
    def wrapper(*args, **kwargs):
        server.logger.debug(f"{validate_tokens.__name__}: Validating tokens.")
        # check if session has jwt, refresh token, unique id
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
            return Response("No tokens found", status = 500)
        server.logger.debug(f"{wrapper.__name__}: Unique ID check: {unique_id}")
        if not unique_id:
            server.logger.debug(f"{wrapper.__name__}: Unique ID not found, setting.")
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
                return Response("Invalid jwt and refresh token", status = 500)
        server.logger.debug(f"{wrapper.__name__}: Tokens validated, returning to function")
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@server.route('/publish_message', methods = ['POST'])
@validate_tokens
def publish_message():
    '''
        event publisher needs to be generic. It should be able to publish to any queue.
        It should take in the queue name and message to be published.
    '''
    # first get the cookies from the request, get the jwt token and refresh token
        # if valid, push to eventQ, along with the hash of the message using the key described below
    # set up a symmetric key in the crypto service - use a PRF for hashing
        # this symmetric key can be called by publisher to then use the key along with a random number as input to generate an output.
        # this output can be used to generate a hash of the message     if not request:
        # send this random number along with the message to the eventQ
        # consumer can then use the random number along with the key from crypto service to generate the random number to verify the hash
    # Simple hashing for now, using a symmetric key from crypto service
    
    # validate the tokens
    if not request:
        return Response("No request found", status = 500)
    if not request.get_json():
        return Response("No JSON found in request", status = 500)
    if not request.get_json().get('message'):
        return Response("No message found in request", status = 500)
    if not request.get_json().get('queue_name'):
        return Response("No queue_name found in request", status = 500)

    payload = request.get_json()
    message = payload['message']
    queue_name = payload['queue_name']
    # generate the hash of the message
    message_b64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
    message_hash = kms.generate_hmac(message_b64, kms.eventQ_mac_keyId)
    message = {'message': message, 'hash': message_hash}
    # Todo: call crypto service to fetch the symmetric key for hashing, use PRF - pseudo random function
    rabbitmq = RabbitMQ()
    rabbitmq.publish(queue_name = queue_name, message = json.dumps(message))
    rabbitmq.close()
    return Response("Message published successfully", status = 200)

if __name__ == '__main__':
    server.run(host = "0.0.0.0", port = 9989)