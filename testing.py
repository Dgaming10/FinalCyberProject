import pymongo
from bson import ObjectId
from gridfs import GridFS

connection_string = ("mongodb+srv://root:qazpoi12345@cyberprojectdb.5cnsgy6.mongodb.net/?retryWrites"
                                   "=true&w=majority&ssl=true")
client = pymongo.MongoClient(connection_string)
db = client["CyberProjectDB"]
print(db["mails"].find_one({'_id': ObjectId('65da2ff97be6e9f10a41b0a8')}, {}).get("recipients")[0]["email"])
