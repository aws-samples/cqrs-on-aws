from redis.commands.json.path import Path

import boto3
import json
import os
import redis

redis_host = os.environ['REDIS_HOST']
redis_port = os.environ['REDIS_PORT']
r = redis.Redis(host=redis_host, port=redis_port)

sqs_client = boto3.client("sqs")
queue_url = os.environ['SQS_URL']
redis_updater_queue_url = os.environ['REDIS_UPDATER_SQS_URL']

def lambda_handler(event, context):
    for record in event['Records']:
        body = json.loads(record['body'])
        r.set(body['messageId'], context.aws_request_id, nx=True, ex=300)

        if r.get(body['messageId']).decode() == context.aws_request_id:
            message = json.loads(body['Message'])
            event_value = message['value']

            if not r.exists(event_value['id_client']):
                json_value = {'name': event_value['name'],
                              'email': event_value['email'],
                              'total': event_value['order_total'],
                              'last_purchase': event_value['event_date']}
                r.json().set(event_value['id_client'], Path.root_path(), json_value)
            else:
                current_value = r.json().get(event_value['id_client'])
                json_value = {'name': event_value['name'],
                              'email': event_value['email'],
                              'total': event_value['order_total'] + current_value['total'],
                              'last_purchase': event_value['event_date']}
                r.json().set(event_value['id_client'], Path.root_path(), json_value)

            sqs_client.send_message(
                QueueUrl=queue_url,
                MessageBody=str(event_value['id']))
            sqs_client.delete_message(
                QueueUrl=redis_updater_queue_url,
                ReceiptHandle=record['receiptHandle'])