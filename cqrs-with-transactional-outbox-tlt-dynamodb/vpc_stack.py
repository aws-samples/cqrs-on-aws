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
    aws_lambda as lambda_,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
    aws_lambda_event_sources as event_source,
    aws_iam as iam,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_logs as logs,
    aws_pipes as pipes,
    aws_events as events,
    aws_events_targets as targets,
    aws_dynamodb as dynamodb,
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

        vpc.add_interface_endpoint("sqs-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.SQS,
                                   security_groups=[sqs_endpoint_sg],
                                   subnets=ec2.SubnetSelection(
                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                   ),
                                   )

        dynamo_vpcEndpoint = vpc.add_gateway_endpoint("DynamoDbEndpoint",
                                                      service=ec2.GatewayVpcEndpointAwsService.DYNAMODB)
        
        vpc.add_interface_endpoint("secrets-manager-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
                                   subnets=ec2.SubnetSelection(
                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                   ),
                                   security_groups=[secrets_manager_endpoint_sg]
                                   )

        db_sg = ec2.SecurityGroup(self,
                                  "db-sg",
                                  vpc=vpc,
                                  )

        # security group creation
        order_receiver_sg = ec2.SecurityGroup(self,
                                              "order-receiver-sg",
                                              vpc=vpc
                                              )

        clientretriever_sg = ec2.SecurityGroup(self,
                                               "ClientRetrieverSG",
                                               vpc=vpc 
                                               )

        ordereventadapter_sg = ec2.SecurityGroup(self,
                                                 "OrderEventAdapterSG",
                                                 vpc=vpc,
                                                 allow_all_outbound=False
                                                 )
        
        aurora_updater_sg = ec2.SecurityGroup(self,
                                                 "AuroraUpdaterSG",
                                                 vpc=vpc,
                                                 allow_all_outbound=True
                                                 )

        database_creator_sg = ec2.SecurityGroup(self, "database-creator-sg",
                                                vpc=vpc,
                                                description="Security Group that grant a lambda that runs inside a VPC to access RDS Database and create schemas and tables"
                                                )

        lambdaauthorizer_sg = ec2.SecurityGroup(self,
                                                "LambdaAuthorizerSG",
                                                vpc=vpc,
                                                )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(database_creator_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(aurora_updater_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(order_receiver_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(clientretriever_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        # This secret manager its for RDS database. The user is AdminDBUser and the password is random generated
        first_letter = secrets.choice(string.ascii_lowercase)
        allowed_chars = f"{first_letter}{string.ascii_lowercase}{string.digits}"
        username = first_letter + ''.join(secrets.choice(allowed_chars) for i in range(14))

        secret = secretsmanager.Secret(self, "orders-db-changes-cluster-credentials",
                                       generate_secret_string=secretsmanager.SecretStringGenerator(
                                           secret_string_template=json.dumps({"username": username}),
                                           generate_string_key="password",
                                           exclude_punctuation=True,
                                           include_space=False
                                       ))

        password = secret.secret_value_from_json("password")

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
                                      storage_encrypted=True
                                      )

        # ensure vpc and secret manager is created before rds cluster
        cluster.node.add_dependency(vpc)
        cluster.node.add_dependency(secret)

        #Create DynamoDB Stream
        dynamo_table = dynamodb.TableV2(self, "ECommerceData",
                                        partition_key=dynamodb.Attribute(name="pk",
                                                                         type=dynamodb.AttributeType.STRING),
                                        sort_key=dynamodb.Attribute(name="sk",
                                                                    type=dynamodb.AttributeType.STRING),
                                        dynamo_stream=dynamodb.StreamViewType.NEW_IMAGE,
                                        removal_policy=aws_cdk.RemovalPolicy.DESTROY
                                        )

        sqs_Aurora_Updater_Queue = sqs.Queue(self, "sqs_Aurora_Updater_Queue")

        # SNS topic creation
        order_event_topic = sns.Topic(self, "OrderEventTopic")

        # Add KafkaToEmailQueue and KafkaToRedisPersisterQueue to SNS subscriptions
        order_event_topic.add_subscription(subscriptions.SqsSubscription(sqs_Aurora_Updater_Queue))

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
        databasecreator_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                             actions=["dynamodb:GetItem", "dynamodb:PutItem"],
                                                             resources=[dynamo_table.table_arn, 
                                                                        dynamo_table.table_stream_arn]))

        ordereventadapter_role = iam.Role(self, "OrderEventAdapter_role",
                                          assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        ordereventadapter_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        ordereventadapter_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))

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
        
        AuroraUpdater_role = iam.Role(self, "AuroraUpdater_role",
                                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        AuroraUpdater_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        AuroraUpdater_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        AuroraUpdater_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                      actions=["sqs:ReceiveMessage",
                                                                               "sqs:DeleteMessage",
                                                                               "sqs:GetQueueAttributes"],
                                                                      resources=[sqs_Aurora_Updater_Queue.queue_arn]))
        AuroraUpdater_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                      actions=["secretsmanager:GetSecretValue"],
                                                                      resources=[secret.secret_arn]))

        ClientRetriever_role = iam.Role(self, "ClientRetriever_role",
                                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        ClientRetriever_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        ClientRetriever_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        ClientRetriever_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                      actions=["secretsmanager:GetSecretValue"],
                                                                      resources=[secret.secret_arn]))

        OrderReceiver_role = iam.Role(self, "OrderReceiver_role",
                                      assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        OrderReceiver_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        OrderReceiver_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        OrderReceiver_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                             actions=["secretsmanager:GetSecretValue"],
                                                             resources=[secret.secret_arn]))
        OrderReceiver_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                             actions=["dynamodb:GetItem", "dynamodb:PutItem"],
                                                             resources=[dynamo_table.table_arn, 
                                                                        dynamo_table.table_stream_arn]))
        

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
                                                      "SECRET_NAME": secret.secret_name,
                                                      "DYNAMO_TABLE": dynamo_table.table_name
                                                  },
                                                  vpc=vpc,
                                                  security_groups=[database_creator_sg],
                                                  vpc_subnets=ec2.SubnetSelection(
                                                      subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                  )
        
        Aurora_Updater_Lambda = lambda_.Function(self, "AuroraUpdater",
                                                  runtime=lambda_.Runtime.PYTHON_3_12,
                                                  handler="lambda_function.lambda_handler",
                                                  code=lambda_.Code.from_asset(
                                                      os.path.join("./resources/lambda-codes/aurora_updater.zip")),
                                                  role=AuroraUpdater_role,
                                                  environment={
                                                      "DB_HOST": cluster.cluster_endpoint.hostname,
                                                      "DB_NAME": "orders",
                                                      "DB_PORT": "5432",
                                                      "SECRET_NAME": secret.secret_name
                                                  },
                                                  vpc=vpc,
                                                  security_groups=[aurora_updater_sg],
                                                  vpc_subnets=ec2.SubnetSelection(
                                                      subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                  )
        
        Aurora_Updater_Lambda.add_event_source(event_source.SqsEventSource(sqs_Aurora_Updater_Queue))

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

        startup_rule.node.add_metadata("uniqueId", "startup")
        startup_rule.node.add_dependency(DatabaseCreator_lambda)

        ClientRetriever_lambda = lambda_.Function(self, "ClientRetriever",
                                                  runtime=lambda_.Runtime.PYTHON_3_12,
                                                  handler="lambda_function.lambda_handler",
                                                  code=lambda_.Code.from_asset(
                                                      os.path.join("./resources/lambda-codes/client_retriever.zip")),
                                                  role=ClientRetriever_role,
                                                  environment={
                                                      "DB_NAME": "orders",
                                                      "DB_HOST": cluster.cluster_endpoint.hostname,
                                                      "DB_PORT": "5432",
                                                      "SECRET_NAME": secret.secret_name
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
                                                    "DYNAMO_TABLE": dynamo_table.table_name
                                                },
                                                vpc=vpc,
                                                security_groups=[order_receiver_sg],
                                                vpc_subnets=ec2.SubnetSelection(
                                                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                )

        # API Gateway creation with clients/{id_client}/GET and orders/POST
        defaultAuthorizer = apigateway.TokenAuthorizer(self,
                                                       "DefaultAuthorizer",
                                                       handler=LambdaAuthorizer_lambda,
                                                       results_cache_ttl=aws_cdk.Duration.seconds(0)
                                                       )

        # API Gateway creation with clients/{id_client}/GET and orders/POST
        clients_resource = api.root.add_resource("clients")

        client_resource = clients_resource.add_resource("{client}")

        client_resource.add_method("GET",
                                      apigateway.LambdaIntegration(ClientRetriever_lambda),
                                      authorizer=defaultAuthorizer,
                                      method_responses=[{
                                          "statusCode": "200",
                                          "responseModels": {
                                              "application/json": apigateway.Model.EMPTY_MODEL
                                          }
                                      }],
                                      request_parameters={
                                          "method.request.path.client": True
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
                                                                                      actions=[
                                                                                          "dynamodb:DescribeStream",
                                                                                          "dynamodb:GetRecords",
                                                                                          "dynamodb:GetShardIterator",
                                                                                          "dynamodb:ListStreams"],
                                                                                      resources=[
                                                                                          dynamo_table.table_stream_arn]))
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
                                       source=dynamo_table.table_stream_arn,
                                       source_parameters=pipes.CfnPipe.PipeSourceParametersProperty(
                                           dynamo_db_stream_parameters=pipes.CfnPipe.PipeSourceDynamoDBStreamParametersProperty(
                                               starting_position="TRIM_HORIZON", batch_size=10
                                           )
                                       ),
                                       target=order_event_topic.topic_arn,
                                       enrichment=OrderEventAdapter_lambda.function_arn,
                                       desired_state='RUNNING'
                                       )

        OrderEventPipe.node.add_dependency(dynamo_table)
