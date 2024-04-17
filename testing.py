import pymongo
from bson import ObjectId

import globals_module
from Base64 import Base64

client = pymongo.MongoClient(globals_module.CONNECTION_STRING)
db = client["CyberProjectDB"]
print(db["mails"].find_one({'_id': ObjectId('id')}, {}))
print(Base64.Encrypt('name@mun.com'))