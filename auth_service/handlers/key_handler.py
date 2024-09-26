from typing import Tuple
from ..models.keys import Keys
from .crypto_handler import CryptoHandler


class KeyHandler:
    def __init__(self):
        self.pub_keys = {x.name:None for x in Keys}
        self.pvt_keys = {x.name for x in (Keys.REFRESH_TOKEN, Keys.JWT_TOKEN)}
    def get_pub_key(self, key_name: Keys) -> bytes:
        if not self.pub_keys[key_name.name]:
            self.pub_keys[key_name.name] = CryptoHandler.get_public_key(key_name)
        return self.keys[key_name.name]
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
            print("Invalid key_name:", key_name)
            raise Exception("Invalid key_name")
        if not self.pub_keys[key_name.name]:
            key, password = CryptoHandler.get_private_key(key_name)
            self.pvt_keys[key_name.name]['key'] = key
            self.pvt_keys[key_name.name]['password'] = password
        return self.keys[key_name.name]