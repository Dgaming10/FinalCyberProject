import base64
import datetime

import gridfs
import pymongo
from bson import ObjectId


class DataBaseService:
    """
    A class representing a database service.

    Attributes:
    - _connection_string (str): MongoDB connection string.
    - _client: MongoDB client.
    - _db: MongoDB database.

    Methods:
    - __init__: Initialize the database service.
    - __del__: Close the MongoDB client on object deletion.
    - authenticate_user: Authenticate a user based on email and password.
    - get_all_sent_mails: Retrieve all sent mails for a given email.
    - get_all_received_mails: Retrieve all received mails for a given email.
    - email_to_mongo_obj: Convert an email to a MongoDB object.
    - store_email: Store an email in the database.
    - find_email_by_id: Find an email by its ID.
    - store_picture: Store a picture in the database using GridFS.
    - retrieve_picture: Retrieve a picture from the database using GridFS.
    """

    def __init__(self):
        """
        Initialize the database service.
        """
        self._connection_string = ("mongodb+srv://root:qazpoi12345@cyberprojectdb.5cnsgy6.mongodb.net/?retryWrites"
                                   "=true&w=majority&ssl=true")
        self._client = pymongo.MongoClient(self._connection_string)
        self._db = self._client["CyberProjectDB"]
        self._fs = gridfs.GridFS(self._db)

    def __del__(self):
        """
        Close the MongoDB client on object deletion.
        """
        if self._client:
            self._client.close()

    def authenticate_user(self, email, password) -> dict:
        """
        Authenticate a user based on email and password.

        Parameters:
        - email (str): User's email.
        - password (str): User's password.

        Returns:
        dict: User information if authentication is successful, an empty dictionary otherwise.
        """
        user = self._db['users'].find_one({"email": email, "password": base64.b64encode(password.encode()).decode()})
        return user or {}

    def get_all_sent_mails(self, email):
        """
        Retrieve all sent mails for a given email.

        Parameters:
        - email (str): User's email.

        Returns:
        list: List of sent mails.
        """
        ansList = []
        for ans in self._db['mails'].find({
            "sender.email": email,
            'creation_date': {'$lte': datetime.datetime.now()}}, {}):
            ansList.append(ans)
        return ansList

    def get_all_received_mails(self, email):
        """
        Retrieve all received mails for a given email.

        Parameters:
        - email (str): User's email.

        Returns:
        list: List of received mails.
        """
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
        """
        Convert an email to a MongoDB object.

        Parameters:
        - email (str): User's email.

        Returns:
        dict: MongoDB object representing the user.
        """
        ansDICT = self._db['users'].find_one({"email": email}, {})
        print("find one for", email, ansDICT)
        return ansDICT

    def store_email(self, fromMail, toMails, subject, message, creation_date) -> str:
        """
        Store an email in the database.

        Parameters:
        - fromMail (str): Sender's email.
        - toMails (list): List of recipient emails.
        - subject (str): Email subject.
        - message (str): Email message.
        - creation_date: Email creation date.

        Returns:
        str: ID of the stored email.
        """
        senderOBJ = self.email_to_mongo_obj(fromMail)
        toOBJ = []
        for email in toMails:
            tmp = self.email_to_mongo_obj(email)
            if tmp is not None:
                toOBJ.append(tmp)

        if not toOBJ:
            return

        new_item = {
            "message": message,
            "creation_date": creation_date,
            "subject": subject,
            "sender": senderOBJ,
            "recipients": toOBJ
        }

        to_return = self._db["mails"].insert_one(new_item)
        final_ans = str(to_return.inserted_id)

        print('to_return:', final_ans)
        return final_ans

    def find_email_by_id(self, email_id: str):
        """
        Find an email by its ID.

        Parameters:
        - email_id (str): ID of the email to find.

        Returns:
        dict: Found email.
        """
        print("EMAIL ID: ", email_id)
        mail = self._db['mails'].find_one({'_id': ObjectId(email_id)}, {})
        return mail

