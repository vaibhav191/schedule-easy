'''
Mongo
UserDetails:
    1. username (email fetched from get-email) # encrypted
    2. auth credentials (as a json file object - https://ai.google.dev/palm_docs/oauth_quickstart#:~:text=Authorize%20credentials%20for%20a%20desktop%20application%201%20In,download%20button%20to%20save%20the%20JSON%20file.%20)
        encrypt using another set of pub-pvt key, use pub key to encrypt, kept with
        auth server.
    3. jwt id
    4. jwt tkn
    # jwts are signed using pvt keys, kept on aws (stored in cache). pub key fetched
    # from aws

'''

import os
import json
import datetime
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.results import InsertOneResult
from typing import Dict, Any
class MongoDBHandler:
    def __init__(self):
        self.address = os.getenv('MONGO_ADDRESS', 'mongo')
        self.port = os.getenv('MONGO_PORT')

    
    def get_client(self, db: str) -> Database:
        client: MongoClient = MongoClient(self.address + ':' + self.port)
        return client[db]
    
    @staticmethod
    def get_collection(db: Database, collection_name: str) -> Collection:
        collection: Collection = db[collection_name]
        return collection

    @staticmethod
    def insert_one(collection: Collection, data: Dict[str, str]) -> InsertOneResult:
        post_id = collection.insert_one(data).inserted_id
        return post_id
    
    @staticmethod
    def update_one(collection: Collection, query: Dict[str, Any], data: Dict[str, Any]) -> None:
        post_id = collection.update_one(query, {'$set': data})
        return post_id


    @staticmethod
    def fetch_one(collection: Collection, query: Dict[str, Any]) -> Dict[str, Any]:
        data = collection.find_one(query)
        if not data:
            return None
        return data