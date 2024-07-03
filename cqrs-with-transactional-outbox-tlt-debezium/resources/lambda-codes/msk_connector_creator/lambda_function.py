import json
import boto3
import time
import os

bucket_arn = os.environ['BUCKET_ARN']
bucket = os.environ['S3_BUCKET']
security_group = os.environ['SECURITY_GROUP']
service_role = os.environ['SERVICE_ROLE']
subnet1 = os.environ['SUBNETS1']
subnet2 = os.environ['SUBNETS2']
object_key = os.environ['OBJECT_KEY']
secret_name = os.environ['SECRET_NAME']
db_host = os.environ['DB_HOST']
msk_cluster_arn = os.environ['MSK_CLUSTER_ARN']

session = boto3.session.Session()

event_bridge = session.client('events',
                              'us-east-1')

pipes = session.client('pipes',
                       'us-east-1')

kafkaconnect = session.client('kafkaconnect',
                              'us-east-1')
s3 = session.client('s3',
                    'us-east-1')
kafka = session.client('kafka',
                       'us-east-1')
secrets_manager = session.client('secretsmanager',
                                 'us-east-1')
secret_value = secrets_manager.get_secret_value(
    SecretId=secret_name
)
secret = json.loads(secret_value['SecretString'])


def lambda_handler(event, context):
    object = s3.get_object(
        Bucket=bucket,
        Key='security-update-response.json'
    )

    update_security_response = json.loads(object['Body'].read())
    cluster_operation_arn = update_security_response['ClusterOperationArn']

    operation_state = kafka.describe_cluster_operation(
        ClusterOperationArn=cluster_operation_arn
    )

    if operation_state['ClusterOperationInfo']['OperationState'] == 'UPDATE_COMPLETE':
        response_plugin = kafkaconnect.create_custom_plugin(
            contentType='ZIP',
            description='custom connector for MSK',
            location={
                's3Location': {
                    'bucketArn': bucket_arn,
                    'fileKey': object_key
                }
            },
            name='debezium-plugin'
        )

        time.sleep(5)

        msk_bootstrap_servers = kafka.get_bootstrap_brokers(
            ClusterArn=msk_cluster_arn
        )['BootstrapBrokerStringSaslIam']

        kafkaconnect.create_connector(
            capacity={
                'autoScaling': {
                    'maxWorkerCount': 3,
                    'mcuCount': 2,
                    'minWorkerCount': 2,
                    'scaleInPolicy': {
                        'cpuUtilizationPercentage': 20
                    },
                    'scaleOutPolicy': {
                        'cpuUtilizationPercentage': 80
                    }
                },
            },
            connectorConfiguration={
                'connector.class': 'io.debezium.connector.postgresql.PostgresConnector',
                'database.dbname': 'orders',
                'database.user': secret['username'],
                'tasks.max': '1',
                'transforms': 'unwrap',
                'plugin.name': 'pgoutput',
                'internal.key.converter': 'org.apache.kafka.connect.json.JsonConverter',
                'topic.prefix': 'orders',
                'database.hostname': db_host,
                'database.password': secret['password'],
                'value.converter.schemas.enable': 'false',
                'internal.value.converter': 'org.apache.kafka.connect.json.JsonConverter',
                'transforms.unwrap.type': 'io.debezium.transforms.ExtractNewRecordState',
                'table.include.list': 'public.order_event',
                'value.converter': 'org.apache.kafka.connect.json.JsonConverter',
                'key.converter': 'org.apache.kafka.connect.json.JsonConverter'
            },
            connectorName='KafkaOrderEventConnector',
            kafkaCluster={
                'apacheKafkaCluster': {
                    'bootstrapServers': msk_bootstrap_servers,
                    'vpc': {
                        'securityGroups': [
                            security_group,
                        ],
                        'subnets': [
                            subnet1,
                            subnet2
                        ],
                    }
                }
            },
            kafkaClusterClientAuthentication={
                'authenticationType': 'IAM'
            },
            kafkaClusterEncryptionInTransit={
                'encryptionType': 'TLS'
            },
            kafkaConnectVersion='2.7.1',
            plugins=[
                {
                    'customPlugin': {
                        'customPluginArn': response_plugin['customPluginArn'],
                        'revision': response_plugin['revision']
                    }
                },
            ],
            serviceExecutionRoleArn=service_role
        )

        event_bridge.put_rule(
            Name='mskConnectorCreatorRule',
            ScheduleExpression='rate(1 minute)',
            State='DISABLED'
        )

        pipes.start_pipe(
            Name='OrderEventPipe'
        )

        return {
            'statusCode': 200,
            'body': 'Debezium Connector created successfully.'
        }
