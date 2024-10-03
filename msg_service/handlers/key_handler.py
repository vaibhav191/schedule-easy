import logging
from typing import Tuple
from models.keys import Keys
from handlers.crypto_handler import CryptoHandler
import logging

class KeyHandler:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    def __init__(self):
        self.pub_keys = {x.name:None for x in Keys}
    def get_pub_key(self, key_name: Keys) -> bytes:
        KeyHandler.logger.debug(f"{KeyHandler.__name__}, {KeyHandler.get_pub_key.__name__}: Current public keys: {self.pub_keys}")
        if not self.pub_keys[key_name.name]:
            KeyHandler.logger.debug(f"{KeyHandler.__name__}, {KeyHandler.get_pub_key.__name__}: Getting public key for {key_name.name}")
            crypto_handler = CryptoHandler()
            self.pub_keys[key_name.name] = crypto_handler.get_public_key(key_name)
        return self.pub_keys[key_name.name]