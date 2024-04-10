import json
import os
import redis

redis_host = os.environ['REDIS_HOST']
redis_port = os.environ['REDIS_PORT']
r = redis.Redis(host=redis_host, port=redis_port)

def lambda_handler(event, context):
    id_client = event['pathParameters']['id_client']
    if not r.exists(id_client):
        return {
            'statusCode': 404,
            'body': 'Client not found'
        }
    else:
        current_value = r.json().get(id_client)
        return {
            'statusCode': 200,
            'body': json.dumps(current_value)
        }