import base64
import requests
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.fernet import Fernet
from ..models.keys import Keys
from ..models.key_types import KeyTypes
import os
from typing import Tuple

class CryptoHandler:
    """
    CryptoHandler class provides methods to handle cryptographic operations such as key retrieval, encryption, and decryption.
    Attributes:
        key_types (dict): A dictionary mapping key names to their types (public, private, symmetric).
        Crypto_host (str): The host address of the crypto service.
        Crypto_port (str): The port number of the crypto service.
    Methods:
        get_public_key(key_name: Keys) -> bytes:
            Retrieves the public key for the given key name from the crypto service.
            Args:
                key_name (Keys): The name of the key to retrieve.
            Returns:
                bytes: The public key in bytes.
            Raises:
                Exception: If the key name is invalid or the public key is not available.
        get_symmetric_key(key_name: Keys) -> bytes:
            Retrieves the symmetric key for the given key name from the crypto service.
            Args:
                key_name (Keys): The name of the key to retrieve.
            Returns:
                bytes: The symmetric key in bytes.
            Raises:
                Exception: If the key name is invalid or the symmetric key is not available.
        asymm_encrypt(data: bytes, key: bytes) -> bytes:
            Encrypts the given data using the provided public key.
            Args:
                data (bytes): The data to encrypt.
                key (bytes): The public key to use for encryption.
            Returns:
                bytes: The encrypted data.
            Raises:
                Exception: If the key or data is invalid, or encryption fails.
        asymm_decrypt(ciphertext: bytes, key_name: Keys) -> bytes:
            Decrypts the given ciphertext using the private key stored in the crypto service.
            Args:
                ciphertext (bytes): The data to decrypt.
                key_name (Keys): The name of the key to use for decryption.
            Returns:
                bytes: The decrypted data.
            Raises:
                Exception: If the key name or data is invalid, or decryption fails.
        symm_encrypt(data: bytes, key: bytes) -> bytes:
            Encrypts the given data using the provided symmetric key.
            Args:
                data (bytes): The data to encrypt.
                key (bytes): The symmetric key to use for encryption.
            Returns:
                bytes: The encrypted data.
        symm_decrypt(data: bytes, key: bytes) -> bytes:
            Decrypts the given data using the provided symmetric key.
            Args:
                data (bytes): The data to decrypt.
                key (bytes): The symmetric key to use for decryption.
            Returns:
                bytes: The decrypted data.
        sign(data: bytes) -> bytes:
            Signs the given data.
            Args:
                data (bytes): The data to sign.
            Returns:
                bytes: The signature.
        verify(data: bytes) -> bytes:
            Verifies the given data.
            Args:
                data (bytes): The data to verify.
            Returns:
                bytes: The verification result.
    """

    key_types = {
        Keys.OAUTH_CREDENTIALS: {KeyTypes.pub, KeyTypes.pvt},
        Keys.JWT_TOKEN: {KeyTypes.pub, KeyTypes.pvt},
        Keys.REFRESH_TOKEN: {KeyTypes.pub, KeyTypes.pvt},
        Keys.REDIS_ENCRYPTION: {KeyTypes.symmetric},
    }

    Crypto_host = os.getenv('CRYPTO_HOST')
    Crypto_port = os.getenv('CRYPTO_PORT')

    @staticmethod
    def get_public_key(key_name: Keys) -> bytes:
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
        
        url = f"http://{CryptoHandler.Crypto_host}:{CryptoHandler.Crypto_port}/get-key"
        key_details = {'key_name': key_name.name, 
                    }
        response = requests.post(url, json = {'key_details': key_details})
        if response.status_code == 200:
            print(f"Key received from crypto service, response: {response.content}")
            if key_name.name in response.json():
                key_b64 = response.json()[key_name.name]
                return base64.b64decode(key_b64)
        else:
            print(f"Failed to get key from crypto service, response: {response.content}, status code: {response.status_code}")  
            raise Exception("Failed to get key from crypto service")
    
    @staticmethod
    def get_private_key(key_name: Keys) -> Tuple[bytes, bytes]:
        """
        Retrieves the private key for the specified key name from the crypto service.
        Args:
            key_name (Keys): The name of the key to retrieve. Must be a member of the Keys enum.
        Returns:
            bytes: The private key in bytes.
        Raises:
            Exception: If the key_name is invalid or if the private key is not available for the given key_name.
            Exception: If the request to the crypto service fails.
        Notes:
            - The private key requested must either be of type REFRESH_TOKEN or JWT_TOKEN.
            - The function constructs the endpoint URL based on the key_name and sends a POST request to the crypto service.
            - If the response status code is 200, it decodes the base64-encoded key from the response and returns it.
            - If the response status code is not 200, it raises an exception.
        """
        if key_name not in CryptoHandler.key_types:
            raise Exception("Invalid key_name")
        if KeyTypes.pvt not in CryptoHandler.key_types[key_name]:
            raise Exception("Private key not available for the given key_name")
        
        if key_name == Keys.REFRESH_TOKEN:
            endpoint = '/get-refresh-pvt-key'
        elif key_name == Keys.JWT_TOKEN:
            endpoint = '/get-jwt-pvt-key'
        else:
            print("Invalid key_name:", key_name)
            raise Exception("Invalid key_name")    
        url = f"http://{CryptoHandler.Crypto_host}:{CryptoHandler.Crypto_port}" + endpoint
        response = requests.post(url)
        if response.status_code == 200:
            print(f"Key received from crypto service, response: {response.content}")
            if key_name.name in response.json():
                key_b64 = response.json()[key_name.name]
                key = base64.b64decode(key_b64)
                password = None
                if 'password' in response.json():
                    password_b64 = response.json()['password']
                    password = base64.b64decode(password_b64) 
                return key, password
        else:
            print(f"Failed to get key from crypto service, response: {response.content}, status code: {response.status_code}")  
            raise Exception("Failed to get key from crypto service")

    @staticmethod
    def get_symmetric_key(key_name: Keys) -> bytes:
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
        
        url = f"http://{CryptoHandler.Crypto_host}:{CryptoHandler.Crypto_port}/get-key"
        key_details = {'key_name': key_name.name}
        response = requests.post(url, params = {'key_details': key_details})
        if response.status_code == 200:
            print(f"Key received from crypto service, response: {response.content}")
            if key_name.name in response.json():
                key_b64 = response.json()[key_name.name]
                return base64.b64decode(key_b64)
        else:
            print(f"Failed to get key from crypto service, response: {response.content}, status code: {response.status_code}")  
            raise Exception("Failed to get key from crypto service")

    @staticmethod
    def asymm_encrypt(data: bytes, key: bytes ) -> bytes:
        """
        Encrypts the given data using the provided public key with asymmetric encryption.
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

    @staticmethod
    def asymm_decrypt(ciphertext: bytes, key_name: Keys) -> bytes:
        """
        Decrypts the given ciphertext using an asymmetric decryption method.
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

        url = f"http://{CryptoHandler.Crypto_host}:{CryptoHandler.Crypto_port}/decrypt"
        key_details = {'key_name': key_name.name, 'ciphertext': ciphertext_b64}
        print("Key Details:", key_details)
        response = requests.post(url, json = key_details)
        print("Response:", response.content, response.status_code)
        if response.status_code == 200:
            print(f"Data received from crypto service, response: {response.content}")
            if 'plaintext' in response.json():
                plaintext_b64 = response.json()['plaintext']
                return base64.b64decode(plaintext_b64)
        else:
            print(f"Failed to get data from crypto service, response: {response.content}, status code: {response.status_code}")  
            raise Exception("Failed to get data from crypto service")
    
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
            print("Key must be of type bytes", type(key))
            raise Exception("Key must be of type bytes") 
        if type(data) is not bytes:
            print("Data must be of type bytes", type(data))
            raise Exception("Data must be of type bytes")
        f = Fernet(key)
        return f.encrypt(data)

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