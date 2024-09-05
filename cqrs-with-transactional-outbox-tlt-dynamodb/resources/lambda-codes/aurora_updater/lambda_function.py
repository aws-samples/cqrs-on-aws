from aws_lambda_powertools import Logger

import boto3
import json
import os
import pg8000

session = boto3.session.Session()
client = session.client('secretsmanager',
                        'us-east-1')

db_name = os.environ['DB_NAME']
host = os.environ['DB_HOST']
port = os.environ['DB_PORT']
secret_name = os.environ['SECRET_NAME']

secret_value = client.get_secret_value(SecretId=secret_name)
secret = json.loads(secret_value['SecretString'])


conn = pg8000.connect(database=db_name, user=secret['username'], host=host, port=port,
                      password=secret['password'])
conn.autocommit = False

logger = Logger()

def lambda_handler(event, context):
    client_data = json.loads(json.loads(event['Records'][0]['body'])['Message'])
    cur = conn.cursor()
    select_statement = "select count(*) from public.client where email = %s"

    try:
        cur.execute(select_statement, (client_data['email'], ))
        client_count = cur.fetchone()[0]

        if client_count == 0:
            insert_statement = "INSERT INTO public.client(name, email, total, last_purchase) VALUES (%s, %s, %s, %s)"
            cur.execute(insert_statement, (client_data['name'], client_data['email'], client_data['total'], client_data['last_purchase']))
        else:
            select_statement = "select total from public.client where email = %s"
            cur.execute(select_statement, (client_data['email'], ))
            total = cur.fetchone()[0]
            total += float(client_data['total'])
            update_statement = "UPDATE public.client SET total = %s, last_purchase = %s WHERE email = %s"
            cur.execute(update_statement, (total, client_data['last_purchase'], client_data['email']))
        conn.commit()
        logger.info(f"Client {client_data['email']} updated")
    except Exception as e:
        logger.exception(e)
        conn.rollback()
        raise e