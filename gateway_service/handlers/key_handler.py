from typing import Tuple
from models.keys import Keys
from handlers.crypto_handler import CryptoHandler

class KeyHandler:
    def __init__(self):
        self.pub_keys = {x.name:None for x in Keys}
    def get_pub_key(self, key_name: Keys) -> bytes:
        if not self.pub_keys[key_name.name]:
            crypto_handler = CryptoHandler()
            self.pub_keys[key_name.name] = crypto_handler.get_public_key(key_name)
        return self.pub_keys[key_name.name]