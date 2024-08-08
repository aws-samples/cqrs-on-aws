import boto3
import json
import os

replication_task_arn = os.environ['REPLICATION_TASK_ARN']
session = boto3.session.Session()
dms = session.client('dms')
def lambda_handler(event, context):
    dms.start_replication_task(
        ReplicationTaskArn=replication_task_arn,
        StartReplicationTaskType='start-replication'
    )