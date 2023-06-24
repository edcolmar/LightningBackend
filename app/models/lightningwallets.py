import jwt
import datetime
from factory.validation import Validator
from factory.database import Database

from ..settings import *

class LightningWallets(object):
    def __init__(self):
        self.validator = Validator()
        self.db = Database()

        self.collection_name = 'lightningwallets'  # collection name

        self.fields = {
            "publickey": "string",
            "userid": "string",
            "userconnected": "bool", 
            "emailaddress": "string",
            "emailvalidated": "bool", 
            "bech_32_url": "string",
            "k1": "string",
            "created": "datetime",
            "updated": "datetime",
        }

        self.create_required_fields = ["publickey", "k1", "userid", "userconnected", "emailaddress", "emailvalidated", "bech_32_url"]

        # Fields optional for CREATE
        self.create_optional_fields = []

        # Fields required for UPDATE
        self.update_required_fields = ["id"]

        # Fields optional for UPDATE
        self.update_optional_fields = [ "publickey", "userid", "userconnected", "emailaddress", "emailvalidated", "bech_32_url", "k1", "created", "updated"]

    def create(self, lightningwallet):
        # Validator will throw error if invalid
        self.validator.validate(lightningwallet, self.fields, self.create_required_fields, self.create_optional_fields)
        res = self.db.insert(lightningwallet, self.collection_name)
        return "Inserted Id " + res

    def find(self, lightningwallet):  # find all
        return self.db.find(lightningwallet, self.collection_name)
    
    def find_by_publickey(self, publickey):
        found = self.db.find_one({"publickey": publickey}, self.collection_name)
        #if found is None:
        #    return not found
        #if "_id" in found:
        #     found["_id"] = str(found["_id"])
        return found
    
    def find_by_k1(self, k1):
        found = self.db.find_one({"k1": k1}, self.collection_name)
        #if found is None:
        #    return not found
        #if "_id" in found:
        #     found["_id"] = str(found["_id"])
        return found
    
    def find_by_bech_32_url(self, bech_32_url):
        found = self.db.find_one({"bech_32_url": bech_32_url}, self.collection_name)
        #if found is None:
        #    return False
        #if "_id" in found.keys():
        #     found["_id"] = str(found["_id"])
        return found

    def find_by_id(self, id):
        return self.db.find_by_id(id, self.collection_name)

    def update(self, id, lightningwallet):
        self.validator.validate(lightningwallet, self.fields, self.update_required_fields, self.update_optional_fields)
        return self.db.update(id, lightningwallet,self.collection_name)

    def delete(self, id):
        return self.db.delete(id, self.collection_name)
    
    def encode_auth_token(self, wallet_id):
        """
        Generates the Auth Token
        :return: string
        """
        #try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1, seconds=0),
            'iat': datetime.datetime.utcnow(),
            'sub': wallet_id
        }
        return jwt.encode(
            payload,
            JWT_SECRET_KEY,
            algorithm='HS256'
        )
        #except Exception as e:
        #    return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Validates the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, JWT_SECRET_KEY)
            #is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            #if is_blacklisted_token:
            #    return 'Token blacklisted. Please log in again.'
            #else:
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'
