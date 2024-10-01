from typing import Tuple
from models.keys import Keys
from handlers.crypto_handler import CryptoHandler

class KeyHandler:
    def __init__(self):
        self.pub_keys = {x.name:None for x in Keys}
        self.pvt_keys = {x.name:None for x in (Keys.REFRESH_TOKEN, Keys.JWT_TOKEN)}
    def get_pub_key(self, key_name: Keys) -> bytes:
        if not self.pub_keys[key_name.name]:
            crypto_handler = CryptoHandler()
            self.pub_keys[key_name.name] = crypto_handler.get_public_key(key_name)
        return self.pub_keys[key_name.name]
    def get_pvt_key(self, key_name: Keys) -> Tuple[bytes, bytes]:
        """
        Retrieves the private key and its associated password for a given key name.

        Args:
            key_name (Keys): The name of the key to retrieve.

        Returns:
            Tuple[bytes, bytes]: A tuple containing the private key and its password.

        Raises:
            Exception: If the provided key_name is not valid.
        """
        if key_name.name not in self.pvt_keys:
            raise Exception("Invalid key_name")
        if not self.pvt_keys[key_name.name]:
            crypto_handler = CryptoHandler()
            key, password = crypto_handler.get_private_key(key_name)
            self.pvt_keys[key_name.name] = {'key': key, 'password': password}
        return self.pvt_keys[key_name.name]['key'], self.pvt_keys[key_name.name]['password']