from redis.commands.json.path import Path

import json
import os
import redis

redis_host = os.environ['REDIS_HOST']
redis_port = os.environ['REDIS_PORT']
r = redis.Redis(host=redis_host, port=redis_port)


def lambda_handler(event, context):
    body = json.loads(event['Records'][0]['body'])
    r.set(body['messageId'], context.aws_request_id, 'NX', 'EX', 300)

    if r.get(body['messageId']) == context.aws_request_id:
        if not r.exists(body['id_client']):
            json_value = {'name': body['name'],
                          'email': body['email'],
                          'total': body['order_total'],
                          'last_purchase': body['event_date']}
            r.json().set(body['id_client'], Path.root_path(), json_value)
        else:
            current_value = r.json().get(body['id_client'])
            json_value = {'name': body['name'],
                          'email': body['email'],
                          'total': body['order_total'] + current_value['total'],
                          'last_purchase': body['event_date']}
            r.json().set(body['id_client'], Path.root_path(), json_value)
