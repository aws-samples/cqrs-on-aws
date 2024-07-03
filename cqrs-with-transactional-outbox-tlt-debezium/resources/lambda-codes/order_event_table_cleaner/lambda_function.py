import boto3
import json
import os
import pg8000

secret_name = os.environ['SECRET_NAME']

session = boto3.session.Session()
client = session.client('secretsmanager',
                        'us-east-1')

secret_value = client.get_secret_value(SecretId=secret_name)
secret = json.loads(secret_value['SecretString'])

db_host = os.environ['DB_HOST']
db_name = os.environ['DB_NAME']
db_port = os.environ['DB_PORT']

conn = pg8000.connect(database=db_name,
                      user=secret['username'],
                      host=db_host,
                      port=db_port,
                      password=secret['password'])
conn.autocommit = False

def lambda_handler(event, context):
    for record in event['Records']:
        id_order_event_record = record['body']

        delete_statement = "DELETE FROM public.order_event WHERE id = %s"
        cur = conn.cursor()
        try:
            cur.execute(delete_statement, (id_order_event_record, ))
            conn.commit()
        except:
            conn.rollback()
        cur.close()