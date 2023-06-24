from factory.validation import Validator
from factory.database import Database


class LightningChallenges(object):
    def __init__(self):
        self.validator = Validator()
        self.db = Database()

        self.collection_name = 'lightningchallenges'  # collection name

        self.fields = {
            "session": "string",
            "secret": "string",
            "k1": "string",
            "bech_32_url": "string",
            "created": "datetime",
            "updated": "datetime",
            "publickey": "string"
        }

        self.create_required_fields = ["k1", "bech_32_url"]

        # Fields optional for CREATE
        self.create_optional_fields = []

        # Fields required for UPDATE
        self.update_required_fields = ["k1"]

        # Fields optional for UPDATE
        self.update_optional_fields = []

    def create(self, lightningchallenge):
        # Validator will throw error if invalid
        self.validator.validate(lightningchallenge, self.fields, self.create_required_fields, self.create_optional_fields)
        res = self.db.insert(lightningchallenge, self.collection_name)
        return "Inserted Id " + res

    def find(self, lightningchallenge):  # find all
        return self.db.find(lightningchallenge, self.collection_name)

    def find_by_id(self, id):
        return self.db.find_by_id(id, self.collection_name)
    
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

    def update(self, id, lightningchallenge):
        self.validator.validate(lightningchallenge, self.fields, self.update_required_fields, self.update_optional_fields)
        return self.db.update(id, lightningchallenge,self.collection_name)

    def delete(self, id):
        return self.db.delete(id, self.collection_name)
