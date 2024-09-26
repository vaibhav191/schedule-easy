from ..models.keys import Keys
from .crypto_handler import CryptoHandler


class KeyHandler:
    """
    A class to manage and retrieve cryptographic keys.

    Attributes:
    -----------
    keys : dict
        A dictionary that maps key names (from the Keys enum) to their corresponding cryptographic keys.

    Methods:
    --------
    __init__():
        Initializes the KeyWallet with a dictionary of keys set to None.
    
    get_key(key_name: Keys) -> bytes:
        Retrieves the public key for the given key name. If the key is not already cached, it fetches the key using the CryptoHandler(which requests the same from crypto_service) and stores it in the keys dictionary.
    """
    def __init__(self):
        self.pub_keys = {x.name:None for x in Keys}
        self.pvt_keys = {x.name for x in (Keys.REFRESH_TOKEN, Keys.JWT_TOKEN)}
    def get_pub_key(self, key_name: Keys) -> bytes:
        if not self.pub_keys[key_name.name]:
            self.pub_keys[key_name.name] = CryptoHandler.get_public_key(key_name)
        return self.keys[key_name.name]
    def get_pvt_key(self, key_name: Keys) -> bytes:
        if key_name.name not in self.pvt_keys:
            print("Invalid key_name:", key_name)
            raise Exception("Invalid key_name")
        return CryptoHandler.get_private_key(key_name)
