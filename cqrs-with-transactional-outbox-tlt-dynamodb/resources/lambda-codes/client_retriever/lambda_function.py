from aws_lambda_powertools import Logger

import boto3
import datetime
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

logger = Logger()

def lambda_handler(event, context):
    print('event:')
    print(event)
    client = event['pathParameters']['client']
    cur = conn.cursor()
    select_statement = "select count(*) from public.client where name = %s"

    try:
        cur.execute(select_statement, (client,))
        client_count = cur.fetchone()[0]
        if client_count == 0:
            return {
                'statusCode': 404,
                'body': 'Client not found'
            }
        else:
            select_statement = "select name, email, total, last_purchase from public.client where name = %s"
            cur.execute(select_statement, (client,))
            client_data = cur.fetchone()

            formatted_value = {
                "name": client_data[0],
                "email": client_data[1],
                "total": client_data[2],
                "last_purchase": datetime.datetime.fromtimestamp(client_data[3]).strftime('%Y-%m-%d %H:%M:%S')
            }

            return {
                'statusCode': 200,
                'body': json.dumps(formatted_value)
            }
    except Exception as e:
        logger.exception(e)
        return {
            'statusCode': 500,
            'body': 'An internal error occured.'
        }