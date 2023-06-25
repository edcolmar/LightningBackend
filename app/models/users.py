import jwt
import datetime
from factory.validation import Validator
from factory.database import Database

from ..settings import *

class Users(object):
    def __init__(self):
        self.validator = Validator()
        self.db = Database()

        self.collection_name = 'users'  # collection name

        self.fields = {
            "name": "string",
            "address": "string",
            "emailaddress": "string",
            "created": "datetime",
            "updated": "datetime",
        }

        self.create_required_fields = ["emailaddress"]

        # Fields optional for CREATE
        self.create_optional_fields = []

        # Fields required for UPDATE
        self.update_required_fields = ["name", "address"]

        # Fields optional for UPDATE
        self.update_optional_fields = []

    def create(self, user):
        # Validator will throw error if invalid
        self.validator.validate(user, self.fields, self.create_required_fields, self.create_optional_fields)
        res = self.db.insert(user, self.collection_name)
        return res

    def find(self, user):  # find all
        return self.db.find(user, self.collection_name)

    def find_by_id(self, id):
        return self.db.find_by_id(id, self.collection_name)
    
    def find_by_emailaddress(self, emailaddress):
        found = self.db.find_one({"emailaddress": emailaddress}, self.collection_name)
        #if found is None:
        #    return not found
        #if "_id" in found:
        #     found["_id"] = str(found["_id"])
        return found

    def update(self, id, user):
        self.validator.validate(user, self.fields, self.update_required_fields, self.update_optional_fields)
        return self.db.update(id, user,self.collection_name)

    def delete(self, id):
        return self.db.delete(id, self.collection_name)
    

