import datetime
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
        formatted_value = {
            "name": current_value["name"],
            "email": current_value["email"],
            "total": current_value["total"],
            "last_purchase": datetime.datetime.fromtimestamp(current_value["last_purchase"]).strftime('%Y-%m-%d %H:%M:%S')
        }

        return {
            'statusCode': 200,
            'body': json.dumps(formatted_value)
        }