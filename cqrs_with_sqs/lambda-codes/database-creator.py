from aws_lambda_powertools import Logger

import boto3
import json
import os
import pg8000

session = boto3.session.Session()
client = session.client('secretsmanager',
                        'us-east-1')

secret_value = client.get_secret_value(SecretId='orders-db-changes-cluster-credentials')
secret = json.loads(secret_value['SecretString'])

db_name = os.environ['DB_NAME']

logger = Logger()

def lambda_handler(event, context):
    conn = pg8000.connect(database=db_name, user=secret['username'], host=secret['host'], port=secret['port'], password=secret['password'])
    conn.autocommit = True
    cur = conn.cursor()

    try:
        cur.execute('''
                    set search_path to public;
                    ''')

        cur.execute('''
                    create table if not exists public.product(
                        "id" serial primary key,
                        "name" varchar not null,
                        "price" float not null
                    );''')

        cur.execute('''
                    create table if not exists public.client(
                        "id" serial primary key,
                        "name" varchar not null,
                        "email" varchar not null
                    );''')

        cur.execute('''
                    create table if not exists public.order(
                        "id" serial primary key,
                        "id_client" serial not null,
                        "placement_date" int not null,
                        constraint fk_client foreign key (id_client) references public.client(id)
                    );''')

        cur.execute('''
                    create table if not exists public.order_item(
                        "id" serial primary key,
                        "id_order" serial not null,
                        "id_product" serial not null,
                        "price_when_item_was_ordered" float not null,
                        "quantity" int not null,
                        constraint fk_product foreign key (id_product) references public.product(id),
                        constraint fk_order foreign key (id_order) references public.order(id)
                    );''')

        cur.execute('''
                    insert into public.product(name, price) values ('Computer', 1500),
                                                                   ('Phone', 500),
                                                                   ('TV', 1000);
                    ''')

        cur.execute('''
                    insert into public.client(name, email) values ('Bob', 'bob@anemailprovider.com'),
                                                                  ('Alice', 'alice@anemailprovider.com'),
                                                                  ('John', 'john@anemailprovider.com');
                    ''')

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