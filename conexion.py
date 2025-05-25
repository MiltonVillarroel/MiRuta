import redis
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

def redis_conexion():
    r = redis.Redis(
        host='redis-14619.c82.us-east-1-2.ec2.redns.redis-cloud.com',
        port=14619,
        decode_responses=True,
        username="default",
        password="1234",
    )
    return r

def mongo_conexion():
    uri = "mongodb+srv://default:1234@transporte.wno4bef.mongodb.net/?retryWrites=true&w=majority&appName=transporte"
    client = MongoClient(uri, server_api=ServerApi('1'))
    return client['miruta']





