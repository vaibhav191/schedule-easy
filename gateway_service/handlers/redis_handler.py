from logging import Logger
import os
import json
from redis import Redis, client
from typing import Dict, Union

# what else do we need it for except login? maybe some active session details?
class RedisHandler:
    def __init__(self) -> None:
        self.host = os.getenv('REDIS_HOST', 'redis')
        self.port = os.getenv('REDIS_PORT')
        self.decode_responses = True
        self.redis_client = Redis(host = self.host, port = self.port, decode_responses= self.decode_responses)

    def get_client(self) -> client.Redis:
        return self.redis_client

    def set(self, key: str, data: Union[str, Dict], logger: Logger) -> bool:
        if not data:
            logger.debug(f"Redis set Data is empty")
            raise ValueError("Data cannot be empty")
        data = json.dumps(data)
        logger.debug(f"Redis set Data: {data}")
        return self.redis_client.set(key, data)
    
    def get(self, key: Union[str, Dict], logger:Logger) -> Union[str, Dict[str, str]]:
        logger.debug(f"Redis get key: {key}")
        if not key:
            logger.debug(f"Redis get Key is empty")
            raise ValueError("Key cannot be empty")
        data = self.redis_client.get(key)
        if not data:
            return None
        data = json.loads(data)
        logger.debug(f"Redis Data received: {data}")
        return data
    
    def delete(self, key) -> None:
        self.redis_client.delete(key)