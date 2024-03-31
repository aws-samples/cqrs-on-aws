import json
import os
import aws_cdk
import base64
import string
import secrets
from random import SystemRandom
from constructs import Construct

from aws_cdk import (
    aws_ec2 as ec2,
    aws_rds as rds,
    aws_apigateway as apigateway,
    aws_elasticache as elasticache,
    aws_lambda as lambda_,
    aws_secretsmanager as secretsmanager,
    aws_sqs as sqs,
    aws_lambda_event_sources as event_source,
    aws_iam as iam,
    Stack,
    aws_events as events,
    aws_logs as logs,
    aws_events_targets as targets,
    Duration
)


class VpcStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # VPC Creation with 2 public subnets and 2 private subnets
        vpc = ec2.Vpc(self, "orders-vpc",
                      ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
                      nat_gateways=1,

                      subnet_configuration=[
                          ec2.SubnetConfiguration(
                              cidr_mask=24,
                              subnet_type=ec2.SubnetType.PUBLIC,
                              name="PublicSubnet"
                          ),

                          ec2.SubnetConfiguration(
                              cidr_mask=24,
                              subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                              name="PrivateSubnetA"
                          )
                      ]
                      )

        vpc.add_flow_log("CQRS-vpcFlowLog")

        # Creation of security groups for vpc endpoint
        secrets_manager_sg = ec2.SecurityGroup(self, "secrets-manager-endpoint-sg",
                                               vpc=vpc,
                                               allow_all_outbound=False,
                                               description="Its a Security Group to allow access to a lambda function that receives requests from API Gateway"
                                               )

        sqs_sg = ec2.SecurityGroup(self, "sqs-sg",
                                   vpc=vpc,
                                   allow_all_outbound=False,
                                   description="Its a Security Group to allow lambda access (inside VPC) to SQS Queue"
                                   )

        # Creation of 3 vpc interface endpoint
        vpc.add_interface_endpoint("sqs-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.SQS,
                                   security_groups=[sqs_sg],
                                   subnets=ec2.SubnetSelection(
                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                   ),
                                   )

        vpc.add_interface_endpoint("secrets-manager-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
                                   subnets=ec2.SubnetSelection(
                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                   ),
                                   security_groups=[secrets_manager_sg]
                                   )

        # Creation of security groups for the rest of the infraestructure
        order_receiver_sg = ec2.SecurityGroup(self, "order-receiver-sg",
                                              vpc=vpc,
                                              description="This is a security group for a Lambda Function that receives HTTP requests from API Gateway."
                                              )

        database_creator_sg = ec2.SecurityGroup(self, "database-creator-sg",
                                                vpc=vpc,
                                                description="Security Group that grant a lambda that runs inside a VPC to access RDS Database and create schemas and tables"
                                                )

        db_sg = ec2.SecurityGroup(self, "db-sg",
                                  vpc=vpc,
                                  description="Allow all ip inbound traffic, but only from Database Creator Lambda, OrderReceiver Lambda, and DB Jumpboxsg"
                                  )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(database_creator_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        db_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(order_receiver_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        redis_sg = ec2.SecurityGroup(self, "redis-sg",
                                     vpc=vpc,
                                     allow_all_outbound=False,
                                     description="Allow all inbound, but only from the source privateserversg, ordereventredispersistersg, and clientretrieversg"
                                     )

        order_event_redis_persister_sg = ec2.SecurityGroup(self, "order-event-redis-persister-sg",
                                                           vpc=vpc,
                                                           description="This sg does not haves inbound rules, only outbound"
                                                           )

        redis_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(order_event_redis_persister_sg.security_group_id),
            connection=ec2.Port.tcp(6378)
        )

        client_retriever_sg = ec2.SecurityGroup(self, "client-retriever-sg",
                                                vpc=vpc,
                                                description="This sg does not haves inbound rules, only outbound"
                                                )

        redis_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(client_retriever_sg.security_group_id),
            connection=ec2.Port.tcp(6378)
        )

        client_retriever_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(redis_sg.security_group_id),
            connection=ec2.Port.tcp(6378)
        )

        order_receiver_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(db_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        order_receiver_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(sqs_sg.security_group_id),
            connection=ec2.Port.all_traffic()
        )

        order_receiver_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(secrets_manager_sg.security_group_id),
            connection=ec2.Port.all_traffic()
        )

        sqs_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(order_receiver_sg.security_group_id),
            connection=ec2.Port.all_traffic()
        )

        secrets_manager_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(order_receiver_sg.security_group_id),
            connection=ec2.Port.all_traffic()
        )

        lambda_authorizer_sg = ec2.SecurityGroup(self, "lambda-authorizer-sg",
                                                 allow_all_outbound=True,
                                                 vpc=vpc,
                                                 description="It is a sg group for a lambda that authorizer the request pass the Api Gateway using ApiKey"
                                                 )

        lambda_authorizer_sg.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.all_traffic()
        )

        # This is the secret manager of the RDS database. The user is random generated and password is random generated

        first_letter = secrets.choice(string.ascii_lowercase)
        allowed_chars = f"{first_letter}{string.ascii_lowercase}{string.digits}-"
        username = ''.join(secrets.choice(allowed_chars) for i in range(15))

        secret = secretsmanager.Secret(self, "orders-db-changes-cluster-credentials",
                                       generate_secret_string=secretsmanager.SecretStringGenerator(
                                           secret_string_template=json.dumps({"username": username}),
                                           generate_string_key="password",
                                           exclude_punctuation=True,
                                           include_space=False
                                       ))

        password = secret.secret_value_from_json("password")

        # Creation of 3 postgres Aurora Clusters
        cluster = rds.DatabaseCluster(self, "orders", default_database_name="orders",
                                      engine=rds.DatabaseClusterEngine.aurora_postgres(
                                          version=rds.AuroraPostgresEngineVersion.VER_15_3),
                                      credentials=rds.Credentials.from_username(username, password=password),
                                      writer=rds.ClusterInstance.provisioned("orders_writer",
                                                                             publicly_accessible=False),
                                      readers=[
                                          rds.ClusterInstance.provisioned("orders_reader", publicly_accessible=False)],
                                      vpc_subnets=ec2.SubnetSelection(
                                          subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                      ),
                                      vpc=vpc,
                                      security_groups=[db_sg],
                                      storage_encrypted=True
                                      )

        # Ensure vpc and secret manager is created before rds cluster
        cluster.node.add_dependency(vpc)
        cluster.node.add_dependency(secret)

        # Creation of subnetgroup for elasticache
        elasticache_subnet_group = elasticache.CfnSubnetGroup(self, "Elasticache_subnet_group",
                                                              description="subnetgroup",
                                                              subnet_ids=vpc.select_subnets(
                                                                  subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                              .subnet_ids
                                                              )

        # Creation of Elasticahe Cluster inside the private subnets
        redis_cluster = elasticache.CfnCacheCluster(self,
                                                    "orders-db-cache",
                                                    engine="redis",
                                                    cache_node_type="cache.t4g.micro",
                                                    num_cache_nodes=1,
                                                    cache_subnet_group_name=elasticache_subnet_group.ref,
                                                    vpc_security_group_ids=[redis_sg.security_group_id],
                                                    port=6378
                                                    )

        # Ensure vpc is created before redis
        redis_cluster.node.add_dependency(vpc)

        dead_letter_queue = sqs.DeadLetterQueue(max_receive_count=5,
                                                queue=sqs.Queue(self, "DeadLetterQueue",
                                                                encryption=sqs.QueueEncryption.SQS_MANAGED,
                                                                enforce_ssl=True,
                                                                retention_period=Duration.days(14),
                                                                visibility_timeout=Duration.seconds(30)
                                                                )
                                                )

        # SQS creation, this topic is connected to Event Redis Updater lambda
        sqs_ordersevent = sqs.Queue(self, "Orderevent",
                                    encryption=sqs.QueueEncryption.SQS_MANAGED,
                                    enforce_ssl=True,
                                    retention_period=Duration.days(14),
                                    visibility_timeout=Duration.seconds(30),
                                    dead_letter_queue=dead_letter_queue)

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
                                     types=[apigateway.EndpointType.REGIONAL]
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
        apigateway.ApiKey(self, "admin_key", api_key_name="admin_key", value=base64_str)

        # Lambda roles
        databasecreator_role = iam.Role(self, "DatabaseCreator_role",
                                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))

        databasecreator_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        databasecreator_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        databasecreator_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                               actions=["secretsmanager:GetSecretValue"],
                                                               resources=[secret.secret_arn]))

        ordereventredisupdater_role = iam.Role(self, "OrderEventRedisUpdater_role",
                                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        ordereventredisupdater_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        ordereventredisupdater_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))

        orderreceiver_role = iam.Role(self, "OrderReceiver_role",
                                      assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        orderreceiver_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        orderreceiver_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        orderreceiver_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                             actions=["secretsmanager:GetSecretValue"],
                                                             resources=[secret.secret_arn]))
        orderreceiver_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                             actions=["sqs:SendMessage"],
                                                             resources=[sqs_ordersevent.queue_arn]))

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

        clientretriever_role = iam.Role(self, "ClientRetriever_role",
                                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        clientretriever_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        clientretriever_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))

        # Lambdas Creation
        LambdaAuthorizer_lambda = lambda_.Function(self, "LambdaAuthorizer",
                                                   runtime=lambda_.Runtime.PYTHON_3_12,
                                                   handler="lambda_function.lambda_handler",
                                                   code=lambda_.Code.from_asset(os.path.join(
                                                       "./lambda-codes/lambda_authorizer.zip")),
                                                   role=lambdaAuthorizer_role,
                                                   vpc=vpc,
                                                   security_groups=[lambda_authorizer_sg],
                                                   vpc_subnets=ec2.SubnetSelection(
                                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                   )

        DatabaseCreator_lambda = lambda_.Function(self, "DatabaseCreator",
                                                  runtime=lambda_.Runtime.PYTHON_3_12,
                                                  handler="lambda_function.lambda_handler",
                                                  code=lambda_.Code.from_asset(os.path.join(
                                                      "./lambda-codes/database_creator.zip")),
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

        # Grant access of Database Creator Lambda do access RDS cluster
        cluster.grant_connect(DatabaseCreator_lambda, "AdminDBUser")
        secret.grant_read(DatabaseCreator_lambda)

        # Automatic execution of DabaseCreator lambda with a EventBridge rule
        startup_rule = events.Rule(self,
                                   "LambdaStartupRule",
                                   enabled=True,
                                   event_pattern=events.EventPattern(source=["aws.cloudformation"],
                                                                     resources=[aws_cdk.Stack.of(self).stack_id],
                                                                     region=[aws_cdk.Aws.REGION],
                                                                     detail_type=["CloudFormation Stack Status Change"],
                                                                     detail={
                                                                         "stack-id": [aws_cdk.Stack.of(self).stack_id],
                                                                         "status-details": {
                                                                             "status": ["CREATE_COMPLETE",
                                                                                        "UPDATE_COMPLETE"]
                                                                         }
                                                                     }
                                                                     ),
                                   rule_name="databaseCreatorStartupRule",
                                   description="Rule to startup DataBase Creator lambda after deployment"
                                   )
        startup_rule.add_target(targets.LambdaFunction(DatabaseCreator_lambda,
                                                       max_event_age=aws_cdk.Duration.hours(1),
                                                       retry_attempts=4))

        startup_rule.node.add_metadata("uniqueId", "startup")
        startup_rule.node.add_dependency(DatabaseCreator_lambda)

        OrderEventRedisUpdater_lambda = lambda_.Function(self, "OrderEventRedisUpdater",
                                                         runtime=lambda_.Runtime.PYTHON_3_12,
                                                         handler="lambda_function.lambda_handler",
                                                         code=lambda_.Code.from_asset(os.path.join(
                                                             "./lambda-codes/order_event_redis_updater.zip")),
                                                         role=databasecreator_role,
                                                         environment={
                                                             "REDIS_HOST": redis_cluster.attr_redis_endpoint_address,
                                                             "REDIS_PORT": "6378"
                                                         },
                                                         vpc=vpc,
                                                         security_groups=[order_event_redis_persister_sg],
                                                         vpc_subnets=ec2.SubnetSelection(
                                                             subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                         )

        # add SQS trigger to Order Event Redis Updater
        OrderEventRedisUpdater_lambda.add_event_source(event_source.SqsEventSource(sqs_ordersevent))

        OrderReceiver_lambda = lambda_.Function(self, "OrderReceiver",
                                                runtime=lambda_.Runtime.PYTHON_3_12,
                                                handler="lambda_function.lambda_handler",
                                                code=lambda_.Code.from_asset(os.path.join(
                                                    "./lambda-codes/order_receiver.zip")),
                                                role=orderreceiver_role,
                                                environment={
                                                    "DB_HOST": cluster.cluster_endpoint.hostname,
                                                    "DB_NAME": "orders",
                                                    "SQS_URL": sqs_ordersevent.queue_url,
                                                    "DB_PORT": "5432",
                                                    "SECRET_NAME": secret.secret_name
                                                },
                                                vpc=vpc,
                                                security_groups=[order_receiver_sg],
                                                vpc_subnets=ec2.SubnetSelection(
                                                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                )

        # Granting permitions to Order Receiver lambda access RDS and Secret Manager
        cluster.grant_connect(OrderReceiver_lambda, "AdminDBUser")
        secret.grant_read(OrderReceiver_lambda)

        ClientRetriever_lambda = lambda_.Function(self, "ClientRetriever",
                                                  runtime=lambda_.Runtime.PYTHON_3_12,
                                                  handler="lambda_function.lambda_handler",
                                                  code=lambda_.Code.from_asset(os.path.join(
                                                      "./lambda-codes/client_retriever.zip")),
                                                  role=clientretriever_role,
                                                  environment={
                                                      "REDIS_HOST": redis_cluster.attr_redis_endpoint_address,
                                                      "REDIS_PORT": "6378"
                                                  },
                                                  vpc=vpc,
                                                  security_groups=[client_retriever_sg],
                                                  vpc_subnets=ec2.SubnetSelection(
                                                      subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                  )

        # Authorizer creation for Api Gateway
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
