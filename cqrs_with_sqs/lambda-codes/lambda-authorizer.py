import base64
import boto3
import re

client = boto3.client('apigateway')

def lambda_handler(event, context):
    authorizationToken = event['authorizationToken'] if 'authorizationToken' in event else event['headers']['Authorization']
    if not re.match("^Basic (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", authorizationToken):
        return get_unauthorized_access(event)

    b64_token = authorizationToken.split(' ')[-1]
    username, token = base64.b64decode(b64_token).decode("utf-8").split(':')
    response = client.get_api_keys(nameQuery='admin_key', includeValues=True)

    if response['items'][0]['value'] != b64_token:
        return get_unauthorized_access(event)
    else:
        return get_allowed_access(username, token, event)


def get_unauthorized_access(event):
    return get_policy(None, None, 'Deny', event)


def get_allowed_access(principalId, usageIdentifierKey, event):
    return get_policy(principalId, usageIdentifierKey, 'Allow', event)


def get_policy(principalId, usageIdentifierKey, effect, event):
    return {
        'principalId': principalId,
        'usageIdentifierKey': usageIdentifierKey,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': event['methodArn']
            }]
        }
    }