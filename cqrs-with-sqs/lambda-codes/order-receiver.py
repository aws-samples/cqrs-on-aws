from aws_lambda_powertools import Logger

import boto3
import calendar
import json
import os
import pg8000
import time
import uuid

session = boto3.session.Session()
client = session.client('secretsmanager',
                        'us-east-1')

sqs_client = session.client('sqs',
                            'us-east-1')

secret_value = client.get_secret_value(SecretId=os.environ['SECRET_NAME'])
secret = json.loads(secret_value['SecretString'])

db_host = os.environ['DB_HOST']
db_name = os.environ['DB_NAME']
db_port = os.environ['DB_PORT']
queue_url = os.environ['SQS_URL']

conn = pg8000.connect(database=db_name, user=secret['username'], host=db_host, port=db_port, password=secret['password'])
conn.autocommit = False

logger = Logger()

def lambda_handler(event, context):
    cur = conn.cursor()
    cur.execute("SELECT nextval('order_id_seq')")
    next_order_id = cur.fetchone()[0]

    gmt = time.gmtime()
    now = calendar.timegm(gmt)

    insert_statement = "INSERT INTO public.order(id, id_client, placement_date) VALUES (%s, %s, %s)"

    try:
        cur.execute(insert_statement, (next_order_id, event['id_client'], now))
        order_total = 0

        for product in event["products"]:
            select_statement = "select price from public.product where id = %s"
            cur.execute(select_statement, str(product['id_product']))
            product_price = cur.fetchone()[0]

            insert_statement = "INSERT INTO public.order_item(id_order, id_product, price_when_item_was_ordered, quantity) VALUES (%s, %s, %s, %s)"
            cur.execute(insert_statement, (next_order_id, product["id_product"], product_price, product["quantity"]))

            order_total += product_price * product["quantity"]

        select_statement = "select name, email from public.client where id = %s"
        cur.execute(select_statement, str(event["id_client"]))
        client = cur.fetchone()

        order_event = {
            'messageId': str(uuid.uuid4()),
            "id_client": event["id_client"],
            "name": client[0],
            "email": client[1],
            "order_total": order_total,
            "event_date": now
        }

        sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(order_event))

        conn.commit()

        return {
            'statusCode': 200,
            'body': 'Order created successfully!'
        }
    except Exception as e:
        logger.exception(e)
        conn.rollback()
        return {
            'statusCode': 500,
            'body': 'An internal error occurred.'
        }