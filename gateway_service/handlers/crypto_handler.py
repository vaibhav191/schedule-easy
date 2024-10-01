import base64
import requests
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.fernet import Fernet
from models.keys import Keys
from models.key_types import KeyTypes
import os

class CryptoHandler:

    key_types = {
        Keys.OAUTH_CREDENTIALS: {KeyTypes.pub, KeyTypes.pvt},
        Keys.JWT_TOKEN: {KeyTypes.pub, KeyTypes.pvt},
        Keys.REFRESH_TOKEN: {KeyTypes.pub, KeyTypes.pvt},
        Keys.REDIS_ENCRYPTION: {KeyTypes.symmetric},
    }

    def __init__(self):
        self.Crypto_host = os.getenv('CRYPTO_HOST', 'crypto_service')
        self.Crypto_port = os.getenv('CRYPTO_PORT', '7070')

    def get_public_key(self, key_name: Keys) -> bytes:
        """
        Retrieves the public key for the given key name from the crypto service.
        Args:
            key_name (Keys): The name of the key to retrieve.
        Returns:
            bytes: The public key in bytes.
        Raises:
            Exception: If the key_name is invalid or the public key is not available.
            Exception: If the request to the crypto service fails.
        """
        if key_name not in CryptoHandler.key_types:
            raise Exception("Invalid key_name")
        if KeyTypes.pub not in CryptoHandler.key_types[key_name]:
            raise Exception("Public key not available for the given key_name")
        
        url = f"http://{self.Crypto_host}:{self.Crypto_port}/get-key"
        key_details = {'key_name': key_name.name, 
                    }
        response = requests.post(url, json = {'key_details': key_details})
        if response.status_code == 200:
            
            if key_name.name in response.json():
                key_b64 = response.json()[key_name.name]
                return base64.b64decode(key_b64)
        else:
            
            raise Exception("Failed to get key from crypto service")
    
    def get_symmetric_key(self, key_name: Keys) -> bytes:
        """
        Retrieves a symmetric key from the crypto service.
        Args:
            key_name (Keys): The name of the key to retrieve.
        Returns:
            bytes: The symmetric key in bytes.
        Raises:
            Exception: If the key_name is invalid or if the symmetric key is not available for the given key_name.
            Exception: If the request to the crypto service fails.
        Notes:
            - The function checks if the provided key_name is valid and if a symmetric key is available for it.
            - It sends a POST request to the crypto service to retrieve the key.
            - If the request is successful and the key is found in the response, it decodes the key from base64 and returns it.
            - If the request fails, it raises an exception with the appropriate error message.
        """
        if key_name not in CryptoHandler.key_types:
            raise Exception("Invalid key_name")
        if KeyTypes.symmetric not in CryptoHandler.key_types[key_name]:
            raise Exception("Symmetric Key not available for the given key_name")
        
        url = f"http://{self.Crypto_host}:{self.Crypto_port}/get-key"
        key_details = {'key_name': key_name.name}
        response = requests.post(url, params = {'key_details': key_details})
        if response.status_code == 200:
            
            if key_name.name in response.json():
                key_b64 = response.json()[key_name.name]
                return base64.b64decode(key_b64)
        else:
            
            raise Exception("Failed to get key from crypto service")

    @staticmethod
    def asymm_encrypt(data: bytes, key: bytes ) -> bytes:
        """
        Encrypts the given data using the provided public key with asymmetric encryption.
        Max encryption size is 190 bytes, any data larger will be encrypted in chunks.
        Args:
            data (bytes): The data to be encrypted. Must be of type bytes.
            key (bytes): The public key used for encryption. Must be of type bytes.
        Returns:
            bytes: The encrypted data.
        Raises:
            Exception: If the key is not of type bytes.
            Exception: If the data is not of type bytes.
            Exception: If the public key serialization fails.
            Exception: If the encryption process fails.
        """
        
        if not key or type(key) is not bytes:
            raise Exception("Key must be of type bytes")
        if type(data) is not bytes:
            raise Exception("Data must be of type bytes")
        try:
            public_key = serialization.load_pem_public_key(key)
        except Exception as e:
            
            raise Exception("Public key serialization failed, check key")
        if len(data) <= 190:
            try:
                
                
                ciphertext = public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                
                raise Exception("Failed to encrypt data. Check data.")

            return ciphertext
        try:
            
            
            ciphertext = b''
            for i in range(0, len(data), 190):
                chunk = data[i:i+190]
                ciphertext += public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
        except Exception as e:
            
            raise Exception("Failed to encrypt data. Check data.")
        return ciphertext

    def asymm_decrypt(self, ciphertext: bytes, key_name: Keys) -> bytes:
        """
        Decrypts the given ciphertext using an asymmetric decryption method.
        Max decryption size is 256 bytes, any data larger will be decrypted in chunks.
        Args:
            ciphertext (bytes): The encrypted data to be decrypted.
            key_name (Keys): The name of the key to be used for decryption. Must be one of Keys.OAUTH_CREDENTIALS, Keys.JWT_TOKEN, or Keys.REFRESH_TOKEN.
        Returns:
            bytes: The decrypted plaintext.
        Raises:
            Exception: If key_name is invalid or not provided.
            Exception: If ciphertext is not of type bytes.
            Exception: If the private key is not available for the given key_name.
            Exception: If the decryption service fails to return a valid response.
        """
        
        if not key_name or type(key_name) is not Keys or key_name not in {Keys.OAUTH_CREDENTIALS, Keys.JWT_TOKEN, Keys.REFRESH_TOKEN}:
            raise Exception("Invalid key_name")
        if type(ciphertext) is not bytes:
            raise Exception("Data must be of type bytes")
        if KeyTypes.pvt not in CryptoHandler.key_types[key_name]:
            raise Exception("Private key not available for the given key_name")

        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

        url = f"http://{self.Crypto_host}:{self.Crypto_port}/decrypt"
        key_details = {'key_name': key_name.name, 'ciphertext': ciphertext_b64}
        
        response = requests.post(url, json = key_details)
        
        if len(ciphertext) <= 256:
            if response.status_code == 200:
                
                if 'plaintext' in response.json():
                    plaintext_b64 = response.json()['plaintext']
                    return base64.b64decode(plaintext_b64)
            else:
                
                raise Exception("Failed to get data from crypto service")
        plaintext = b''
        for i in range(0, len(ciphertext), 256):
            chunk = ciphertext[i:i+256]
            chunk_b64 = base64.b64encode(chunk).decode('utf-8')
            key_details = {'key_name': key_name.name, 'ciphertext': chunk_b64}
            response = requests.post(url, json = key_details)
            if response.status_code == 200:
                
                if 'plaintext' in response.json():
                    plaintext_b64 = response.json()['plaintext']
                    plaintext += base64.b64decode(plaintext_b64)
            else:
                
                raise Exception("Failed to get data from crypto service")
        return plaintext

    @staticmethod
    def symm_encrypt(data: bytes, key: bytes) -> bytes:
        """
        Encrypts the given data using symmetric encryption with the provided key.
        Args:
            data (bytes): The data to be encrypted.
            key (bytes): The encryption key.
        Returns:
            bytes: The encrypted data.
        """
        if not key or type(key) is not bytes:
            
            raise Exception("Key must be of type bytes") 
        if type(data) is not bytes:
            
            raise Exception("Data must be of type bytes")
        f = Fernet(key)
        return f.encrypt(data)

    @staticmethod
    def symm_decrypt(data: bytes, key: bytes) -> bytes:
        """
        Decrypts the given data using the provided symmetric key.

        Args:
            data (bytes): The encrypted data to be decrypted.
            key (bytes): The symmetric key used for decryption.

        Returns:
            bytes: The decrypted data.
        """
        f = Fernet(key)
        return f.decrypt(data)

    @staticmethod
    def sign(data: bytes) -> bytes:
        pass

    @staticmethod
    def verify(data: bytes) -> bytes:
        pass