import os
import boto3
# AWS KMS
class KMSHandler:
    '''
        Remember, KMSHandler does not need KMS Access and secret key when running on AWS through IAM roles.
    '''
    def __init__(self) -> None:
        self.access_key = os.getenv('AUTH_KMS_ACCESS_KEY')
        self.secret_key = os.getenv('AUTH_KMS_SECRET_KEY')
        self.region = os.getenv('AUTH_KMS_REGION')
        self.keyID = os.getenv('AUTH_APP_CREDENTIALS_KEYID')
        self.client = boto3.client('kms', region_name = self.region, aws_access_key_id = self.access_key, aws_secret_access_key = self.secret_key)
    
    def encrypt(self, data: bytes) -> bytes:
        resp = self.client.encrypt(KeyId = self.keyID, Plaintext = data, EncryptionContext = {'context': 'google_app_cred'})
        if 'CiphertextBlob' in resp:
            return resp['CiphertextBlob']
        return None

    def decrypt(self, data: bytes) -> bytes:
        resp = self.client.decrypt(CiphertextBlob = data, KeyId = self.keyID, EncryptionContext = {'context': 'google_app_cred'})
        if 'Plaintext' in resp:
            return resp['Plaintext']
        return None
