import boto3
import calendar
import json
import ulid
import os
import time

table_name = os.environ['DYNAMO_TABLE']
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(table_name)

def lambda_handler(event, context):
    ulid_id = ulid.new()
    total = 0
    gmt = time.gmtime()

    for product in event['products']:
        order_item = get_order_item(event['client'], ulid_id, product)
        total += order_item['price_when_item_was_ordered'] * order_item['quantity']

        table.put_item(
            TableName=table_name,
            Item=order_item
        )

    table.put_item(
        TableName=table_name,
        Item=get_order(ulid_id, event['client'], gmt)
    )

    table.put_item(
        TableName=table_name,
        Item=get_order_event(event, ulid_id, total, gmt)
    )

    return {
        'statusCode': 200,
        'body': 'Order created successfully!'
    }

def get_order(ulid, client, gmt):
    return {
        'pk': 'USER#' + client,
        'sk': 'ORDER_PROFILE#' + ulid.str,
        'placement_date': calendar.timegm(gmt)
    }

def get_order_event(event, ulid, total, gmt):
    client_data =  table.get_item(
        Key={
            'pk': 'USER#' + event['client'],
            'sk': 'PROFILE#' + event['client'],
        }
    )

    return {
        'pk': 'USER#' + event['client'],
        'sk': 'ORDER_EVENT#' + ulid.str,
        'name': event['client'],
        'email': client_data['Item']['email'],
        'total': total,
        'last_purchase': calendar.timegm(gmt)
    }

def get_order_item(username, ulid, product):
    product_details = table.get_item(
        TableName=table_name,
        Key={
            'pk': 'PRODUCT#' + product['product'],
            'sk': 'PROFILE#' + product['product'],
        }
    )
    print(product_details)
    return {
        'pk': 'USER#' + username,
        'sk': 'ORDER#' + ulid.str + '#PRODUCT#' + product['product'],
        'price_when_item_was_ordered': product_details['Item']['price'],
        'quantity': product['quantity'],
    }