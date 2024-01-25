import base64
import datetime

import pymongo
from bson import ObjectId


class DataBaseService:
    def __init__(self):
        self._connection_string = ("mongodb+srv://root:qazpoi12345@cyberprojectdb.5cnsgy6.mongodb.net/?retryWrites"
                                   "=true&w=majority&ssl=true")
        self._client = pymongo.MongoClient(self._connection_string)
        self._db = self._client["CyberProjectDB"]

    def __del__(self):
        if self._client:
            self._client.close()

    def authenticate_user(self, email, password) -> dict:
        user = self._db['users'].find_one({"email": email, "password": base64.b64encode(password.encode()).decode()})
        return user or {}

    def get_all_sent_mails(self, email):
        ansList = []
        for ans in self._db['mails'].find({
            "sender.email": email,
            'creation_date': {'$lte': datetime.datetime.now()}}, {}):
            ansList.append(ans)
        return ansList

    def get_all_received_mails(self, email):
        ansList = []
        for ans in self._db['mails'].find({
            "recipients": {
                "$elemMatch": {
                    "email": email
                }
            },
            'creation_date': {'$lte': datetime.datetime.now()}
        }, {}):
            ansList.append(ans)
        return ansList

    def email_to_mongo_obj(self, email) -> dict:
        ansDICT = self._db['users'].find_one({"email": email}, {})
        print("find one for", email, ansDICT)
        return ansDICT

    def store_email(self, fromMail, toMails, subject, message, creation_date) -> str:
        senderOBJ = self.email_to_mongo_obj(fromMail)
        toOBJ = []
        for email in toMails:
            tmp = self.email_to_mongo_obj(email)
            if tmp is not None:
                toOBJ.append(tmp)
        new_item = {
            "message": message,
            "creation_date": creation_date,
            "subject": subject,
            "sender": senderOBJ,
            "recipients": toOBJ
        }

        to_return = self._db["mails"].insert_one(new_item)
        print('to_return:', to_return)
        return str(to_return.inserted_id)

    def find_email_by_id(self, email_id: str):
        print("EMAIL ID: ", email_id)
        mail = self._db['mails'].find_one({'_id': ObjectId(email_id)}, {})
        return mail
