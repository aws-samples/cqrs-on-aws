import base64
import json
import os
import random
import string
import aws_cdk
import secrets
from random import SystemRandom
from constructs import Construct

from aws_cdk import (

    aws_ec2 as ec2,
    aws_rds as rds,
    aws_apigateway as apigateway,
    aws_elasticache as elasticache,
    aws_lambda as lambda_,
    aws_secretsmanager as secretmanager,
    aws_sqs as sqs,
    aws_lambda_event_sources as event_source,
    aws_iam as iam,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_logs as logs,
    aws_pipes as pipes,
    aws_s3_assets as s3asset,
    aws_events as events,
    aws_events_targets as targets,
    aws_kinesis as kinesis,
    aws_dms as dms,
    SecretValue,
    Stack,
    CfnOutput
)


class VpcStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc(self, "orders-vpc",
                      ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
                      nat_gateways=1,

                      subnet_configuration=[
                          ec2.SubnetConfiguration(
                              cidr_mask=24,
                              subnet_type=ec2.SubnetType.PUBLIC,
                              name="PublicSubnet"
                          ),
                          # Use PRIVATE_WITH_EGRESS instead of PRIVATE_WITH_NAT
                          ec2.SubnetConfiguration(
                              cidr_mask=24,
                              subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                              name="PrivateSubnetA"
                          )
                      ]
                      )

        vpc.add_flow_log("CQRS-vpcFlowLog")

        sqs_endpoint_sg = ec2.SecurityGroup(self, "sqs-endpoint-sg",
                                            vpc=vpc,
                                            allow_all_outbound=False
                                            )

        secrets_manager_endpoint_sg = ec2.SecurityGroup(self, "secrets-manager-endpoint-sg",
                                                        vpc=vpc,
                                                        allow_all_outbound=False
                                                        )

        kinesis_endpoint_sg = ec2.SecurityGroup(self, "kinesis-endpoint-sg",
                                                vpc=vpc,
                                                allow_all_outbound=False
                                                )

        vpc.add_interface_endpoint("sqs-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.SQS,
                                   security_groups=[sqs_endpoint_sg],
                                   subnets=ec2.SubnetSelection(
                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                   ),
                                   )

        vpc.add_interface_endpoint("secrets-manager-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
                                   subnets=ec2.SubnetSelection(
                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                   ),
                                   security_groups=[secrets_manager_endpoint_sg]
                                   )

        vpc.add_interface_endpoint("kinesis-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.KINESIS_STREAMS,
                                   subnets=ec2.SubnetSelection(
                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                   ),
                                   security_groups=[kinesis_endpoint_sg]
                                   )

        db_sg = ec2.SecurityGroup(self,
                                  "db-sg",
                                  vpc=vpc,
                                  )

        # security group creation
        replication_instance_sg = ec2.SecurityGroup(self,
                                                    "replication-instance-sg",
                                                    vpc=vpc
                                                    )

        lambda_to_redis_sg = ec2.SecurityGroup(self,
                                               "LambdaToRedisSG",
                                               vpc=vpc,
                                               allow_all_outbound=False
                                               )

        redis_sg = ec2.SecurityGroup(self, "redis-sg",
                                     vpc=vpc,
                                     allow_all_outbound=False,
                                     description="Allow all inbound, but only from the source privateserversg, ordereventredispersistersg, and clientretrieversg"
                                     )

        order_receiver_sg = ec2.SecurityGroup(self,
                                              "order-receiver-sg",
                                              vpc=vpc
                                              )

        clientretriever_sg = ec2.SecurityGroup(self,
                                               "ClientRetrieverSG",
                                               vpc=vpc,
                                               allow_all_outbound=False
                                               )

        ordereventadapter_sg = ec2.SecurityGroup(self,
                                                 "OrderEventAdapterSG",
                                                 vpc=vpc,
                                                 allow_all_outbound=False
                                                 )

        database_creator_sg = ec2.SecurityGroup(self, "database-creator-sg",
                                                vpc=vpc,
                                                description="Security Group that grant a lambda that runs inside a VPC to access RDS Database and create schemas and tables"
                                                )

        dms_replication_task_starter_sg = ec2.SecurityGroup(self, "dms-replication-task-starter-sg",
                                                            vpc=vpc,
                                                            description="Security Group that grant a lambda that runs inside a VPC to access DMS Replication Task"
                                                            )

        lambdaauthorizer_sg = ec2.SecurityGroup(self,
                                                "LambdaAuthorizerSG",
                                                vpc=vpc,
                                                )

        ordereventtablecleaner_sg = ec2.SecurityGroup(self,
                                                      "OrderEventTableCleanerSG",
                                                      vpc=vpc,
                                                      )

        lambda_to_redis_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(6379)
        )

        lambda_to_redis_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443)
        )

        clientretriever_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(6379)
        )

        redis_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(lambda_to_redis_sg.security_group_id),
            connection=ec2.Port.tcp(6379)
        )

        redis_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(clientretriever_sg.security_group_id),
            connection=ec2.Port.tcp(6379)
        )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(ordereventtablecleaner_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(database_creator_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(order_receiver_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(replication_instance_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        replication_instance_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443)
        )

        replication_instance_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(5432)
        )

        dms_replication_task_starter_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(443)
        )

        # Bucket S3 creation for debezium custom plugin files
        s3_bucket_asset = s3asset.Asset(self, "asset_s3",
                                        path=os.path.join("./resources/files/debezium-connector.zip")
                                        )

        # This secret manager its for RDS database. The user is AdminDBUser and the password is random generated
        first_letter = secrets.choice(string.ascii_lowercase)
        allowed_chars = f"{first_letter}{string.ascii_lowercase}{string.digits}"
        username = first_letter + ''.join(secrets.choice(allowed_chars) for i in range(14))

        parameter_group = rds.ParameterGroup(
            self,
            "cdc-enabled-postgres-group",
            engine=rds.DatabaseClusterEngine.aurora_postgres(
                version=rds.AuroraPostgresEngineVersion.VER_15_3
            ),
            parameters={
                "rds.logical_replication": "1"
            }
        )

        temp_secret = secretmanager.Secret(self, "orders-db-changes-cluster-credentials_temp",
                                           generate_secret_string=secretmanager.SecretStringGenerator(
                                               secret_string_template=json.dumps({"username": username}),
                                               generate_string_key="password",
                                               exclude_punctuation=True,
                                               include_space=False))
        password = temp_secret.secret_value_from_json("password")

        # creation of 3 postgres Aurora Clusters
        cluster = rds.DatabaseCluster(self, "orders", default_database_name="orders",
                                      engine=rds.DatabaseClusterEngine.aurora_postgres(
                                          version=rds.AuroraPostgresEngineVersion.VER_15_3),
                                      credentials=rds.Credentials.from_username(username, password=password),
                                      writer=rds.ClusterInstance.provisioned("writer",
                                                                             publicly_accessible=False),
                                      readers=[
                                          rds.ClusterInstance.provisioned("reader", publicly_accessible=False)],
                                      vpc_subnets=ec2.SubnetSelection(
                                          subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                      ),
                                      vpc=vpc,
                                      security_groups=[db_sg],
                                      storage_encrypted=True,
                                      parameter_group=parameter_group
                                      )

        # ensure vpc and secret manager is created before rds cluster
        cluster.node.add_dependency(vpc)
        cluster.node.add_dependency(temp_secret)

        secret = secretmanager.Secret(self, "orders-db-changes-cluster-credentials",
                                      secret_object_value={
                                          "username": SecretValue.unsafe_plain_text(username),
                                          "password": password,
                                          "host": SecretValue.unsafe_plain_text(cluster.cluster_endpoint.hostname),
                                          "port": SecretValue.unsafe_plain_text(str(cluster.cluster_endpoint.port))
                                      })

        # Kinesis Data Stream
        orders_cdc_stream = kinesis.Stream(self, "orders-cdc-stream",
                                           stream_name="orders-cdc-stream",
                                           encryption=kinesis.StreamEncryption.KMS
                                           )

        # DMS infrastucture roles
        SecretRetriever_role = iam.Role(self, "SecretRetriever_role",
                                        assumed_by=iam.ServicePrincipal(f"dms.{aws_cdk.Aws.REGION}.amazonaws.com"))

        SecretRetriever_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                               actions=["secretsmanager:GetSecretValue"],
                                                               resources=[secret.secret_arn]))

        dms_vpc_role = iam.Role(self, "dms-vpc-role", role_name="dms-vpc-role",
                                assumed_by=iam.ServicePrincipal("dms.amazonaws.com"))

        dms_vpc_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonDMSVPCManagementRole"))

        dmsKinesis_role = iam.Role(self, "dmsKinesis_role",
                                   assumed_by=iam.ServicePrincipal(f"dms.{aws_cdk.Aws.REGION}.amazonaws.com"))

        dmsKinesis_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                          actions=["kinesis:DescribeStream",
                                                                   "kinesis:PutRecord",
                                                                   "kinesis:PutRecords"],
                                                          resources=[orders_cdc_stream.stream_arn]))

        kms_resource = f"arn:aws:kms:{aws_cdk.Aws.REGION}:{aws_cdk.Aws.ACCOUNT_ID}:key/*"

        dmsKinesis_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                          actions=["kms:GenerateDataKey"],
                                                          resources=[kms_resource]))

        # DMS replication subnet group
        replication_subnet_group = dms.CfnReplicationSubnetGroup(self, "replication_subnet_group",
                                                                 replication_subnet_group_description="subnetgroups for instance replication",
                                                                 subnet_ids=vpc.select_subnets(
                                                                     subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids
                                                                 )

        # DMS replication instance
        orders_db_replication_instance = dms.CfnReplicationInstance(self, "orders-db-replication-instance",
                                                                    replication_instance_class="dms.t3.micro",
                                                                    publicly_accessible=False,
                                                                    vpc_security_group_ids=[
                                                                        replication_instance_sg.security_group_id],
                                                                    replication_subnet_group_identifier=replication_subnet_group.ref
                                                                    )

        # DMS source endpoint
        source_endpoint = dms.CfnEndpoint(self, "source_endpoint",
                                          endpoint_type="source",
                                          engine_name="aurora-postgresql",
                                          database_name="orders",
                                          postgre_sql_settings=dms.CfnEndpoint.PostgreSqlSettingsProperty(
                                              secrets_manager_access_role_arn=SecretRetriever_role.role_arn,
                                              secrets_manager_secret_id=secret.secret_full_arn)
                                          )

        # DMS target endpoint
        target_endpoint = dms.CfnEndpoint(self, "target_endpoint",
                                          endpoint_type="target",
                                          engine_name="kinesis",
                                          kinesis_settings=dms.CfnEndpoint.KinesisSettingsProperty(
                                              service_access_role_arn=dmsKinesis_role.role_arn,
                                              message_format="json",
                                              stream_arn=orders_cdc_stream.stream_arn)
                                          )

        # DMS cdc Task
        orders_dms_cdc_task = dms.CfnReplicationTask(self, "orders_dms_cdc_task",
                                                     migration_type="full-load-and-cdc",
                                                     replication_instance_arn=orders_db_replication_instance.ref,
                                                     source_endpoint_arn=source_endpoint.ref,
                                                     target_endpoint_arn=target_endpoint.ref,
                                                     table_mappings=json.dumps({
                                                         "rules": [
                                                             {"rule-type": "selection",
                                                              "rule-id": "656166126",
                                                              "rule-name": "656166126",
                                                              "object-locator": {
                                                                  "schema-name": "public",
                                                                  "table-name": "order_event"
                                                              },
                                                              "rule-action": "include",
                                                              "filters": []
                                                              }]})
                                                     )

        # Creation of subnetgroup for elasticache
        elasticache_subnet_group = elasticache.CfnSubnetGroup(self, "Elasticache_subnet_group",
                                                              description="subnetgroup",
                                                              subnet_ids=vpc.select_subnets(
                                                                  subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                              .subnet_ids
                                                              )

        # Elasticache Cluster creation
        redis_cluster = elasticache.CfnCacheCluster(self,
                                                    "orders-db-cache",
                                                    engine="redis",
                                                    cache_node_type="cache.t4g.micro",
                                                    num_cache_nodes=1,
                                                    cache_subnet_group_name=elasticache_subnet_group.ref,
                                                    vpc_security_group_ids=[redis_sg.security_group_id]
                                                    )

        # ensure vpc is created before redis
        redis_cluster.node.add_dependency(vpc)

        sqs_kafka_to_redis_Persister_queue = sqs.Queue(self, "KafkaToRedisPersisterQueue")

        sqs_order_event_Table_cleaner = sqs.Queue(self, "OrderEventTableCleaner")

        # SNS topic creation
        order_event_topic = sns.Topic(self, "OrderEventTopic")

        # Add KafkaToEmailQueue and KafkaToRedisPersisterQueue to SNS subscriptions
        order_event_topic.add_subscription(subscriptions.SqsSubscription(sqs_kafka_to_redis_Persister_queue))

        # API Gateway and ApiKey creation
        CQRS_log_group = logs.LogGroup(self, "CQRSLogs")

        api = apigateway.RestApi(self, "OrdersAPI",
                                 deploy_options=apigateway.StageOptions(
                                     access_log_destination=apigateway.LogGroupLogDestination(CQRS_log_group),
                                     access_log_format=apigateway.AccessLogFormat.json_with_standard_fields(caller=True,
                                                                                                            http_method=True,
                                                                                                            ip=True,
                                                                                                            protocol=False,
                                                                                                            request_time=True,
                                                                                                            resource_path=True,
                                                                                                            response_length=False,
                                                                                                            status=True,
                                                                                                            user=True)
                                 ),
                                 cloud_watch_role=True,
                                 endpoint_configuration=
                                 apigateway.EndpointConfiguration(
                                     types=[apigateway.EndpointType.REGIONAL
                                            ]
                                 ),
                                 rest_api_name="OrdersAPI")

        # Generate the user and password on Base64 for api_key
        cryptogen = SystemRandom()

        chars = string.ascii_letters + string.digits
        password = ''.join(cryptogen.choice(chars) for i in range(12))
        user_key = ''.join(cryptogen.choice(chars) for i in range(cryptogen.randint(4, 6)))
        combined_str = f"{user_key}:{password}"
        base64_str = base64.b64encode(combined_str.encode()).decode()

        # Creation of the api key resource with a user and password converted to base64
        api_key = apigateway.ApiKey(self, "admin_key", api_key_name="admin_key", value=base64_str)

        # roles
        databasecreator_role = iam.Role(self, "DatabaseCreator_role",
                                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        databasecreator_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        databasecreator_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        databasecreator_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                               actions=["secretsmanager:GetSecretValue"],
                                                               resources=[secret.secret_arn]))

        dms_replication_task_starter_role = iam.Role(self, "DmsReplicationTaskStarter_role",
                                                     assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        dms_replication_task_starter_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        dms_replication_task_starter_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        dms_replication_task_starter_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                            actions=["dms:StartReplicationTask"],
                                                                            resources=[
                                                                                orders_dms_cdc_task.ref]))

        ordereventadapter_role = iam.Role(self, "OrderEventAdapter_role",
                                          assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        ordereventadapter_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        ordereventadapter_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))

        OrderEventRedisPersister_role = iam.Role(self, "OrderEventRedisPersister_role",
                                                 assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        OrderEventRedisPersister_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        OrderEventRedisPersister_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        OrderEventRedisPersister_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        OrderEventRedisPersister_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                        actions=["sqs:DeleteMessage"],
                                                                        resources=[
                                                                            sqs_kafka_to_redis_Persister_queue.queue_arn]))
        OrderEventRedisPersister_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                        actions=["sqs:SendMessage"],
                                                                        resources=[
                                                                            sqs_order_event_Table_cleaner.queue_arn]))

        lambdaAuthorizer_role = iam.Role(self, "LambdaAuthorizer_role",
                                         assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        lambdaAuthorizer_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        lambdaAuthorizer_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        lambdaAuthorizer_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                actions=["apigateway:GET"],
                                                                resources=[
                                                                    f"arn:aws:apigateway:{aws_cdk.Aws.REGION}::/apikeys"]))

        OrderEventTableCleaner_role = iam.Role(self, "OrderEventTableCleaner_role",
                                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        OrderEventTableCleaner_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        OrderEventTableCleaner_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        OrderEventTableCleaner_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaSQSQueueExecutionRole"))
        OrderEventTableCleaner_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                      actions=["secretsmanager:GetSecretValue"],
                                                                      resources=[secret.secret_arn]))

        ClientRetriever_role = iam.Role(self, "ClientRetriever_role",
                                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        ClientRetriever_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        ClientRetriever_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))

        OrderReceiver_role = iam.Role(self, "OrderReceiver_role",
                                      assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        OrderReceiver_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        OrderReceiver_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        OrderReceiver_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                             actions=["secretsmanager:GetSecretValue"],
                                                             resources=[secret.secret_arn]))

        # lambda creation
        LambdaAuthorizer_lambda = lambda_.Function(self, "LambdaAuthorizer",
                                                   runtime=lambda_.Runtime.PYTHON_3_12,
                                                   handler="lambda_function.lambda_handler",
                                                   code=lambda_.Code.from_asset(
                                                       os.path.join("./resources/lambda-codes/lambda_authorizer.zip")),
                                                   role=lambdaAuthorizer_role,
                                                   vpc=vpc,
                                                   security_groups=[lambdaauthorizer_sg],
                                                   vpc_subnets=ec2.SubnetSelection(
                                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                   )

        OrderEventAdapter_lambda = lambda_.Function(self, "OrderEventAdapter",
                                                    runtime=lambda_.Runtime.PYTHON_3_12,
                                                    handler="lambda_function.lambda_handler",
                                                    code=lambda_.Code.from_asset(os.path.join(
                                                        "./resources/lambda-codes/order_event_adapter.zip")),
                                                    role=ordereventadapter_role,
                                                    vpc=vpc,
                                                    security_groups=[ordereventadapter_sg],
                                                    vpc_subnets=ec2.SubnetSelection(
                                                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                    )

        DatabaseCreator_lambda = lambda_.Function(self, "DatabaseCreator",
                                                  runtime=lambda_.Runtime.PYTHON_3_12,
                                                  handler="lambda_function.lambda_handler",
                                                  code=lambda_.Code.from_asset(
                                                      os.path.join("./resources/lambda-codes/database_creator.zip")),
                                                  role=databasecreator_role,
                                                  environment={
                                                      "DB_HOST": cluster.cluster_endpoint.hostname,
                                                      "DB_NAME": "orders",
                                                      "DB_PORT": "5432",
                                                      "SECRET_NAME": secret.secret_name
                                                  },
                                                  vpc=vpc,
                                                  security_groups=[database_creator_sg],
                                                  vpc_subnets=ec2.SubnetSelection(
                                                      subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                  )

        DMSReplicationTaskStarter_lambda = lambda_.Function(self, "DMSReplicationTaskStarter",
                                                            runtime=lambda_.Runtime.PYTHON_3_12,
                                                            handler="lambda_function.lambda_handler",
                                                            code=lambda_.Code.from_asset(
                                                                os.path.join(
                                                                    "./resources/lambda-codes/dms_replication_task_starter.zip")),
                                                            role=dms_replication_task_starter_role,
                                                            environment={
                                                                "REPLICATION_TASK_ARN": orders_dms_cdc_task.ref
                                                            },
                                                            vpc=vpc,
                                                            security_groups=[dms_replication_task_starter_sg],
                                                            vpc_subnets=ec2.SubnetSelection(
                                                                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                            )

        # Grant access of Database Creator Lambda do access RDS cluster
        cluster.grant_connect(DatabaseCreator_lambda, "AdminDBUser")
        secret.grant_read(DatabaseCreator_lambda)

        startup_rule = events.Rule(self,
                                   "DatabaseCreatorStartupRule",
                                   enabled=True,
                                   event_pattern=events.EventPattern(source=["aws.cloudformation"],
                                                                     resources=[aws_cdk.Stack.of(self).stack_id],
                                                                     region=[aws_cdk.Aws.REGION],
                                                                     detail_type=["CloudFormation Stack Status Change"],
                                                                     detail={
                                                                         "stack-id": [aws_cdk.Stack.of(self).stack_id],
                                                                         "status-details": {
                                                                             "status": ["CREATE_COMPLETE"]
                                                                         }
                                                                     }
                                                                     ),
                                   rule_name="databaseCreatorStartupRule",
                                   description="Rule to start the creation of the database."
                                   )

        startup_rule.add_target(targets.LambdaFunction(DatabaseCreator_lambda,
                                                       max_event_age=aws_cdk.Duration.hours(1),
                                                       retry_attempts=4))
        startup_rule.add_target(targets.LambdaFunction(DMSReplicationTaskStarter_lambda,
                                                       max_event_age=aws_cdk.Duration.hours(1),
                                                       retry_attempts=4))

        startup_rule.node.add_metadata("uniqueId", "startup")
        startup_rule.node.add_dependency(DatabaseCreator_lambda)
        startup_rule.node.add_dependency(DMSReplicationTaskStarter_lambda)

        OrderEventRedisPersister_lambda = lambda_.Function(self, "OrderEventRedisPersister",
                                                           runtime=lambda_.Runtime.PYTHON_3_12,
                                                           handler="lambda_function.lambda_handler",
                                                           code=lambda_.Code.from_asset(os.path.join(
                                                               "./resources/lambda-codes/order_event_redis_updater.zip")),
                                                           role=OrderEventRedisPersister_role,
                                                           environment={
                                                               "REDIS_HOST": redis_cluster.attr_redis_endpoint_address,
                                                               "REDIS_PORT": "6379",
                                                               "SQS_URL": sqs_order_event_Table_cleaner.queue_url,
                                                               "REDIS_UPDATER_SQS_URL": sqs_kafka_to_redis_Persister_queue.queue_url
                                                           },
                                                           vpc=vpc,
                                                           security_groups=[lambda_to_redis_sg],
                                                           vpc_subnets=ec2.SubnetSelection(
                                                               subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                           )
        # add SQS trigger
        OrderEventRedisPersister_lambda.add_event_source(
            event_source.SqsEventSource(sqs_kafka_to_redis_Persister_queue))

        OrderEventTableCleaner_lambda = lambda_.Function(self, "OrderEventTableCleaner_lambda",
                                                         runtime=lambda_.Runtime.PYTHON_3_12,
                                                         handler="lambda_function.lambda_handler",
                                                         code=lambda_.Code.from_asset(os.path.join(
                                                             "./resources/lambda-codes/order_event_table_cleaner.zip")),
                                                         role=OrderEventTableCleaner_role,
                                                         environment={
                                                             "DB_HOST": cluster.cluster_endpoint.hostname,
                                                             "DB_NAME": "orders",
                                                             "DB_PORT": "5432",
                                                             "SECRET_NAME": secret.secret_name
                                                         },
                                                         vpc=vpc,
                                                         security_groups=[ordereventtablecleaner_sg],
                                                         vpc_subnets=ec2.SubnetSelection(
                                                             subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                         )
        # add SQS trigger
        OrderEventTableCleaner_lambda.add_event_source(event_source.SqsEventSource(sqs_order_event_Table_cleaner))

        # Granting permitions to lambda access RDS and Secret Manager
        cluster.grant_connect(OrderEventTableCleaner_lambda, "AdminDBUser")
        secret.grant_read(OrderEventTableCleaner_lambda)

        ClientRetriever_lambda = lambda_.Function(self, "ClientRetriever",
                                                  runtime=lambda_.Runtime.PYTHON_3_12,
                                                  handler="lambda_function.lambda_handler",
                                                  code=lambda_.Code.from_asset(
                                                      os.path.join("./resources/lambda-codes/client_retriever.zip")),
                                                  role=ClientRetriever_role,
                                                  environment={
                                                      "REDIS_HOST": redis_cluster.attr_redis_endpoint_address,
                                                      "REDIS_PORT": "6379"
                                                  },
                                                  vpc=vpc,
                                                  security_groups=[clientretriever_sg],
                                                  vpc_subnets=ec2.SubnetSelection(
                                                      subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                  )

        OrderReceiver_lambda = lambda_.Function(self, "OrderReceiver",
                                                runtime=lambda_.Runtime.PYTHON_3_12,
                                                handler="lambda_function.lambda_handler",
                                                code=lambda_.Code.from_asset(
                                                    os.path.join("./resources/lambda-codes/order_receiver.zip")),
                                                role=OrderReceiver_role,
                                                environment={
                                                    "DB_HOST": cluster.cluster_endpoint.hostname,
                                                    "DB_NAME": "orders",
                                                    "DB_PORT": "5432",
                                                    "SECRET_NAME": secret.secret_name
                                                },
                                                vpc=vpc,
                                                security_groups=[order_receiver_sg],
                                                vpc_subnets=ec2.SubnetSelection(
                                                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                )

        # Granting permitions to lambda access RDS and Secret Manager
        cluster.grant_connect(OrderEventTableCleaner_lambda, "AdminDBUser")
        secret.grant_read(OrderEventTableCleaner_lambda)

        # API Gateway creation with clients/{id_client}/GET and orders/POST
        defaultAuthorizer = apigateway.TokenAuthorizer(self,
                                                       "DefaultAuthorizer",
                                                       handler=LambdaAuthorizer_lambda,
                                                       results_cache_ttl=aws_cdk.Duration.seconds(0)
                                                       )

        # API Gateway creation with clients/{id_client}/GET and orders/POST
        clients_resource = api.root.add_resource("clients")

        id_client_resource = clients_resource.add_resource("{id_client}")

        id_client_resource.add_method("GET",
                                      apigateway.LambdaIntegration(ClientRetriever_lambda),
                                      authorizer=defaultAuthorizer,
                                      method_responses=[{
                                          "statusCode": "200",
                                          "responseModels": {
                                              "application/json": apigateway.Model.EMPTY_MODEL
                                          }
                                      }],
                                      request_parameters={
                                          "method.request.path.id_client": True
                                      }
                                      )

        orders_resource = api.root.add_resource("orders")

        orders_resource.add_method("POST",
                                   apigateway.LambdaIntegration(OrderReceiver_lambda, proxy=False,
                                                                integration_responses=[{
                                                                    "statusCode": "200"
                                                                }]),
                                   authorizer=defaultAuthorizer,
                                   method_responses=[{
                                       "statusCode": "200",
                                       "responseModels": {
                                           "application/json": apigateway.Model.EMPTY_MODEL
                                       }
                                   }]
                                   )

        # Event Bridge Pipes
        Amazon_EventBridge_Pipe_OrderEventPipe_role = iam.Role(self, "Amazon_EventBridge_Pipe_OrderEventPipe_role",
                                                               assumed_by=iam.ServicePrincipal("pipes.amazonaws.com"))
        Amazon_EventBridge_Pipe_OrderEventPipe_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                                      actions=["kms:GenerateDataKey",
                                                                                               "kms:Decrypt"],
                                                                                      resources=[kms_resource]))
        Amazon_EventBridge_Pipe_OrderEventPipe_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                                      actions=[
                                                                                          "kinesis:DescribeStream",
                                                                                          "kinesis:DescribeStreamSummary",
                                                                                          "kinesis:GetRecords",
                                                                                          "kinesis:GetShardIterator",
                                                                                          "kinesis:ListStreams",
                                                                                          "kinesis:ListShards"],
                                                                                      resources=[
                                                                                          orders_cdc_stream.stream_arn]))
        Amazon_EventBridge_Pipe_OrderEventPipe_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                                      actions=["lambda:InvokeFunction"],
                                                                                      resources=[
                                                                                          OrderEventAdapter_lambda.function_arn]))
        Amazon_EventBridge_Pipe_OrderEventPipe_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                                      actions=["sns:Publish"],
                                                                                      resources=[
                                                                                          order_event_topic.topic_arn]))

        order_event_pipe_log_group = logs.LogGroup(self, "order_event_pipe_log_group")

        # Event Bridge pipes creation
        OrderEventPipe = pipes.CfnPipe(self,
                                       "OrderEventPipe",
                                       name="OrderEventPipe",
                                       role_arn=Amazon_EventBridge_Pipe_OrderEventPipe_role.role_arn,
                                       source=orders_cdc_stream.stream_arn,
                                       source_parameters=pipes.CfnPipe.PipeSourceParametersProperty(
                                           kinesis_stream_parameters=pipes.CfnPipe.PipeSourceKinesisStreamParametersProperty(
                                               starting_position="LATEST"
                                           )
                                       ),
                                       target=order_event_topic.topic_arn,
                                       enrichment=OrderEventAdapter_lambda.function_arn,
                                       desired_state='RUNNING'
                                       )

        OrderEventPipe.node.add_dependency(orders_cdc_stream)
