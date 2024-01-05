import datetime

import pymongo
import base64
from User import User
from bson import ObjectId


# def mongo_obj_to_User(mongo_dict) -> User:
#     returnedUser = User(mongo_dict['email'], mongo_dict['first_name'], mongo_dict['last_name'], mongo_dict['age'])
#     return returnedUser


class DataBaseService:
    def __init__(self):
        self._connection_string = ("mongodb+srv://root:qazpoi12345@cyberprojectdb.5cnsgy6.mongodb.net/?retryWrites"
                                   "=true&w=majority")

    def authenticate_user(self, email, password) -> dict:
        myClient = pymongo.MongoClient(self._connection_string)
        mydb = myClient["CyberProjectDB"]
        for user in mydb['users'].find({"email": email, "password": base64.b64encode(password.encode()).decode()}, {}):
            myClient.close()
            return user
        return {}

    def get_all_sent_mails(self, email):
        myClient = pymongo.MongoClient(self._connection_string)
        mydb = myClient["CyberProjectDB"]
        ansList = []
        for ans in mydb['mails'].find({"sender.email": email}, {}):
            ansList.append(ans)
        myClient.close()
        return ansList

    def get_all_received_mails(self, email):
        myClient = pymongo.MongoClient(self._connection_string)
        mydb = myClient["CyberProjectDB"]
        ansList = []
        for ans in mydb['mails'].find({
            "recipients": {
                "$elemMatch": {
                    "email": email
                }
            }
        }, {}):
            ansList.append(ans)
        myClient.close()
        return ansList

    def email_to_mongo_obj(self, email) -> dict:
        myClient = pymongo.MongoClient(self._connection_string)
        mydb = myClient["CyberProjectDB"]
        ansDICT = mydb['users'].find_one({"email": email}, {})
        myClient.close()
        return ansDICT

    def store_email(self, fromMail, toMails, subject, message, creation_date):
        myClient = pymongo.MongoClient(self._connection_string)
        mydb = myClient["CyberProjectDB"]
        senderOBJ = self.email_to_mongo_obj(fromMail)
        toOBJ = [self.email_to_mongo_obj(email) for email in toMails]
        new_item = {
            "message": message,
            "creation_date": creation_date,
            "subject": subject,
            "sender": senderOBJ,
            "recipients": toOBJ
        }

        mydb["mails"].insert_one(new_item)

        myClient.close()

    def find_email_by_id(self, email_id: str):
        myClient = pymongo.MongoClient(self._connection_string)
        mydb = myClient["CyberProjectDB"]
        mail = mydb['mails'].find_one({'_id': ObjectId(email_id)}, {})
        myClient.close()
        return mail

