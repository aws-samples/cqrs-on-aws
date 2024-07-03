import json
import boto3
import os

msk_cluster_arn = os.environ['MSK_CLUSTER_ARN']
s3_bucket = os.environ['S3_BUCKET']

session = boto3.session.Session()

kafka = session.client('kafka',
                       'us-east-1')
s3 = session.client('s3',
                    'us-east-1')
event_bridge = session.client('events',
                              'us-east-1')

def lambda_handler(event, context):
    current_version = kafka.describe_cluster(
        ClusterArn=msk_cluster_arn
    )['ClusterInfo']['CurrentVersion']

    response = kafka.update_security(
        ClientAuthentication={
            'Sasl': {
                'Iam': {
                    'Enabled': True
                }
            }
        },
        ClusterArn=msk_cluster_arn,
        CurrentVersion=current_version
    )

    s3.put_object(
        Bucket=s3_bucket,
        Key='security-update-response.json',
        Body=json.dumps(response)
    )

    event_bridge.put_rule(
        Name='mskConnectorCreatorRule',
        ScheduleExpression='rate(1 minute)',
        State='ENABLED'
    )

    return {
        'statusCode': 200,
        'body': 'Security update successfully.'
    }
