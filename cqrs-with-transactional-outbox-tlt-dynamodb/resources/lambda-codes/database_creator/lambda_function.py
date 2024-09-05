from aws_lambda_powertools import Logger

import boto3
import json
import os
import pg8000

session = boto3.session.Session()
client = session.client('secretsmanager',
                        'us-east-1')

secret_value = client.get_secret_value(SecretId=os.environ['SECRET_NAME'])
secret = json.loads(secret_value['SecretString'])

db_host = os.environ['DB_HOST']
db_name = os.environ['DB_NAME']
db_port = os.environ['DB_PORT']
table_name = os.environ['DYNAMO_TABLE']

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(table_name)

logger = Logger()


def lambda_handler(event, context):
    conn = pg8000.connect(database=db_name, user=secret['username'], host=db_host, port=db_port,
                          password=secret['password'])
    conn.autocommit = True
    cur = conn.cursor()

    try:
        cur.execute('''
                    set search_path to public;
                    ''')

        cur.execute('''
                    create table if not exists public.client(
                        "id" serial primary key,
                        "name" varchar not null,
                        "email" varchar not null,
                        "total" float not null,
                        "last_purchase" int not null
                    );''')

        table.put_item(
            TableName=table_name,
            Item={
                'pk': 'PRODUCT#Phone',
                'sk': 'PROFILE#Phone',
                'name': 'Phone',
                'price': 500

            }
        )

        table.put_item(
            TableName=table_name,
            Item={
                'pk': 'PRODUCT#Computer',
                'sk': 'PROFILE#Computer',
                'name': 'Computer',
                'price': 1500

            }
        )

        table.put_item(
            TableName=table_name,
            Item={
                'pk': 'PRODUCT#TV',
                'sk': 'PROFILE#TV',
                'name': 'TV',
                'price': 1000

            }
        )

        table.put_item(
            TableName=table_name,
            Item={
                'pk': 'USER#bob',
                'sk': 'PROFILE#bob',
                'email': 'bob@anemailprovider.com',
                'name': 'Bob'

            }
        )

        table.put_item(
            TableName=table_name,
            Item={
                'pk': 'USER#john',
                'sk': 'PROFILE#john',
                'email': 'john@anemailprovider.com',
                'name': 'John'

            }
        )

        conn.close()
        logger.info('Database created successfully.')
        return {
            'statusCode': 200,
            'body': 'Database created successfully.'
        }
    except Exception as e:
        conn.close()
        logger.exception(e)
        return {
            'statusCode': 500,
            'body': 'An internal error occurred. Check CloudWatch for details.'
        }