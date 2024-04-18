from Base64 import Base64
import datetime

from gridfs import GridFS
import pymongo
from bson import ObjectId
from globals_module import CONNECTION_STRING


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
    - get_all_sent_emails: Retrieve all sent emails for a given email.
    - get_all_received_emails: Retrieve all received emails for a given email.
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
        self._connection_string = CONNECTION_STRING
        self._client = pymongo.MongoClient(self._connection_string)
        self._db = self._client["CyberProjectDB"]
        self._fs = GridFS(self._db)

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
        user = self._db['users'].find_one({"email": {"$eq": email}, "password": {"$eq": password}})
        return user or {}

    def get_all_sent_emails(self, email):
        """
        Retrieve all sent mails for a given email, sorted by date.

        Parameters:
        - email (str): User's email.

        Returns:
        list: List of sent mails sorted by date.
        """
        ansList = []
        for ans in self._db['mails'].find({
            "sender.email": email,
            "deleted": {
                "$nin": [email]
            }
        }).sort("creation_date", -1):  # Sorting by date in descending order
            ansList.append(ans)
        return ansList

    def get_all_received_emails(self, email):
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
            "deleted": {
                "$nin": [email]
            },
            'creation_date': {'$lte': datetime.datetime.now()}
        }, {}).sort("creation_date", -1):
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

    def store_user(self, email, password, first_name, last_name, age) -> str:
        new_item = {
            'email': email,
            'password': password,
            'first_name': first_name,
            'last_name': last_name,
            'age': age
        }
        to_return = self._db["users"].insert_one(new_item)
        final_ans = str(to_return.inserted_id)

        print('to_return:', final_ans)
        return final_ans

    def store_email(self, fromMail, toMails, subject, message, creation_date, files) -> str:
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
            "recipients": toOBJ,
            "files": files,
            "deleted": []
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
        email = self._db['mails'].find_one({'_id': ObjectId(email_id)}, {})
        return email

    def get_files_by_id(self, email_id) -> list:
        final_ans = []
        email = self._db['mails'].find_one({'_id': ObjectId(email_id)}, {})
        for file in email["files"]:
            current_file = self._fs.get(file)
            final_ans.append((current_file.read(), current_file.filex, current_file.filename))

        return final_ans

    def get_file_name_ex_by_id(self, file_id) -> tuple:
        if isinstance(file_id, str):
            file_id = ObjectId(file_id)
        f = self._fs.get(file_id)
        return f.filename, f.filex

    def get_file_content_by_id(self, file_id) -> bytes:
        if isinstance(file_id, str):
            file_id = ObjectId(file_id)
        return self._fs.get(file_id).read()

    def save_files(self, files) -> list:
        final_ans = []
        for tup in files:
            file_i_id = self._fs.put(tup[2], filename=tup[0], filex=tup[1])
            final_ans.append(file_i_id)

        return final_ans

    def delete_email(self, email_tup):
        email_id = email_tup[0]
        if isinstance(email_id, str):
            email_id = ObjectId(email_id)
        email = self._db['mails'].find_one({'_id': email_id}, {})
        recipients_emails = [res_obj['email'] for res_obj in email.get('recipients')]
        deleted_emails = email.get('deleted')
        deleted_emails.append(email_tup[1])
        self._db['mails'].update_one({'_id': email_id}, {'$push': {'deleted': email_tup[1]}})
        if len(deleted_emails) == len(recipients_emails) + 1:
            files_ids = email.get('files')
            self._db['mails'].delete_one({'_id': email_id})
            for file_id in files_ids:
                self._fs.delete(file_id)
