import json
import os
import aws_cdk
import random
import base64
import string
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
    Stack,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions
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
                                               allow_all_outbound=False
                                               )

        queue_sg = ec2.SecurityGroup(self, "sqs-sg",
                                     vpc=vpc,
                                     allow_all_outbound=False
                                     )

        order_events_topic_sg = ec2.SecurityGroup(self, "sns-sg",
                                                  vpc=vpc,
                                                  allow_all_outbound=False
                                                  )

        order_receiver_sg = ec2.SecurityGroup(self, "order-receiver-sg",
                                              allow_all_outbound=True,
                                              vpc=vpc
                                              )

        database_creator_sg = ec2.SecurityGroup(self, "database-creator-sg",
                                                allow_all_outbound=True,
                                                vpc=vpc
                                                )

        order_events_table_poller_lambda_sg = ec2.SecurityGroup(self, "order-events-table-poller-lambda_sg",
                                                                vpc=vpc,
                                                                allow_all_outbound=False
                                                                )

        order_events_cleaner_sqs_sg = ec2.SecurityGroup(self, "order-events-cleaner-sqs-sg",
                                                        vpc=vpc,
                                                        allow_all_outbound=False
                                                        )

        order_events_table_cleaner_lambda_sg = ec2.SecurityGroup(self, "order-events-table-cleaner-sg",
                                                                 vpc=vpc,
                                                                 allow_all_outbound=False
                                                                 )

        db_sg = ec2.SecurityGroup(self, "db-sg",
                                  vpc=vpc
                                  )

        redis_sg = ec2.SecurityGroup(self, "redis-sg",
                                     vpc=vpc,
                                     allow_all_outbound=False
                                     )

        client_retriever_sg = ec2.SecurityGroup(self, "client-retriever-sg",
                                                vpc=vpc
                                                )

        order_event_redis_updater_sg = ec2.SecurityGroup(self, "order-event-redis-persister-sg",
                                                         vpc=vpc,
                                                         allow_all_outbound=True
                                                         )

        lambda_authorizer_sg = ec2.SecurityGroup(self, "lambda-authorizer-sg",
                                                 allow_all_outbound=True,
                                                 vpc=vpc
                                                 )

        # Creation of 3 vpc interface endpoint
        vpc.add_interface_endpoint("sqs-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.SQS,
                                   security_groups=[queue_sg],
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

        vpc.add_interface_endpoint("sns-endpoint",
                                   service=ec2.InterfaceVpcEndpointAwsService.SNS,
                                   subnets=ec2.SubnetSelection(
                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                   ),
                                   security_groups=[order_events_topic_sg]
                                   )

        # Creation of security groups for the rest of the infraestructure

        db_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(5432)
        )

        database_creator_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(db_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        redis_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(order_event_redis_updater_sg.security_group_id),
            connection=ec2.Port.tcp(6379)
        )

        redis_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(client_retriever_sg.security_group_id),
            connection=ec2.Port.tcp(6379)
        )

        client_retriever_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.tcp(6379)
        )

        order_receiver_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(db_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        order_receiver_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(secrets_manager_sg.security_group_id),
            connection=ec2.Port.all_traffic()
        )

        queue_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.all_traffic()
        )

        order_event_redis_updater_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.all_traffic()
        )

        order_events_table_poller_lambda_sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.all_traffic()
        )

        order_events_topic_sg.add_ingress_rule(
            peer=ec2.Peer.security_group_id(order_events_table_poller_lambda_sg.security_group_id),
            connection=ec2.Port.all_traffic()
        )

        order_events_topic_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(queue_sg.security_group_id),
            connection=ec2.Port.all_traffic()
        )

        secrets_manager_sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc.vpc_cidr_block),
            connection=ec2.Port.all_traffic()
        )

        lambda_authorizer_sg.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.all_traffic()
        )

        order_events_table_cleaner_lambda_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(db_sg.security_group_id),
            connection=ec2.Port.tcp(5432)
        )

        order_events_table_cleaner_lambda_sg.add_egress_rule(
            peer=ec2.Peer.security_group_id(secrets_manager_sg.security_group_id),
            connection=ec2.Port.all_traffic()
        )

        # This secret manager its for RDS database. The user is AdminDBUser and the password is random generated
        secret = secretmanager.Secret(self, "orders-db-changes-cluster-credentials",
                                      generate_secret_string=secretmanager.SecretStringGenerator(
                                          secret_string_template='{"username": "AdminDBUser"}',
                                          generate_string_key="password",
                                          exclude_punctuation=True,
                                          include_space=False))

        user_name = secret.secret_value_from_json("username").to_string()
        password = secret.secret_value_from_json("password")

        # Creation of 3 postgres Aurora Clusters
        cluster = rds.DatabaseCluster(self, "orders", default_database_name="orders",
                                      engine=rds.DatabaseClusterEngine.aurora_postgres(
                                          version=rds.AuroraPostgresEngineVersion.VER_15_3),
                                      credentials=rds.Credentials.from_username("AdminDBUser", password=password),
                                      writer=rds.ClusterInstance.provisioned("orders_writer",
                                                                             publicly_accessible=False),
                                      readers=[
                                          rds.ClusterInstance.provisioned("orders_reader", publicly_accessible=False)],
                                      vpc_subnets=ec2.SubnetSelection(
                                          subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                      ),
                                      vpc=vpc,
                                      security_groups=[db_sg]
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
                                                    vpc_security_group_ids=[redis_sg.security_group_id]
                                                    )

        # Ensure vpc is created before redis
        redis_cluster.node.add_dependency(vpc)

        # SQS creation, this topic is connected to Event Redis Updater lambda
        sqs_redis_updater_queue = sqs.Queue(self, "RedisUpdaterQueue")

        order_event_table_cleaner_queue = sqs.Queue(self, "OrderEventTableCleanerQueue")

        # SNS topic creation
        order_event_topic = sns.Topic(self, "OrderEventTopic")

        order_event_topic.add_subscription(subscriptions.SqsSubscription(sqs_redis_updater_queue))

        # API Gateway and ApiKey creation
        api = apigateway.RestApi(self, "OrdersAPI",
                                 endpoint_configuration=
                                 apigateway.EndpointConfiguration(
                                     types=[apigateway.EndpointType.REGIONAL]
                                 ),
                                 rest_api_name="OrdersAPI")

        # Generate the user and password on Base64 for api_key
        chars = string.ascii_letters + string.digits
        user_key = ''.join(random.choice(chars) for i in range(random.randint(4, 6)))
        password_key = ''.join(random.choice(chars) for i in range(random.randint(8, 12)))
        combined_str = f"{user_key}:{password_key}"
        base64_str = base64.b64encode(combined_str.encode()).decode()

        api_key = apigateway.ApiKey(self, "admin_key", api_key_name="admin_key", value=base64_str)

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
        ordereventredisupdater_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                      actions=["sqs:DeleteMessage", "sqs:SendMessage"],
                                                                      resources=[sqs_redis_updater_queue.queue_arn,
                                                                                 order_event_table_cleaner_queue.queue_arn]))

        orderreceiver_role = iam.Role(self, "OrderReceiver_role",
                                      assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        orderreceiver_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        orderreceiver_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        orderreceiver_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                             actions=["secretsmanager:GetSecretValue"],
                                                             resources=[secret.secret_arn]))

        ordereventtablepoller_role = iam.Role(self, "ordereventtable_role",
                                              assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        ordereventtablepoller_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        ordereventtablepoller_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        ordereventtablepoller_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                     actions=["secretsmanager:GetSecretValue"],
                                                                     resources=[secret.secret_arn]))
        ordereventtablepoller_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                     actions=["sns:Publish", "sns:ListTopics"],
                                                                     resources=[order_event_topic.topic_arn]))

        lambdaAuthorizer_role = iam.Role(self, "LambdaAuthorizer_role",
                                         assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        lambdaAuthorizer_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        lambdaAuthorizer_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        lambdaAuthorizer_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                actions=["apigateway:*"],
                                                                resources=[
                                                                    f"arn:aws:apigateway:{aws_cdk.Aws.REGION}::/apikeys"]))

        clientretriever_role = iam.Role(self, "ClientRetriever_role",
                                        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        clientretriever_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        clientretriever_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))

        ordereventtablecleaner_role = iam.Role(self, "OrderEventTableCleaner_role",
                                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        ordereventtablecleaner_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        ordereventtablecleaner_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        ordereventtablecleaner_role.add_to_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                                                      actions=["secretsmanager:GetSecretValue"],
                                                                      resources=[secret.secret_arn]))

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
                                                         role=ordereventredisupdater_role,
                                                         environment={
                                                             "REDIS_HOST": redis_cluster.attr_redis_endpoint_address,
                                                             "REDIS_PORT": "6379",
                                                             "REDIS_UPDATER_SQS_URL": sqs_redis_updater_queue.queue_url,
                                                             "ORDER_EVENT_TABLE_CLEANER_SQS_URL": order_event_table_cleaner_queue.queue_url
                                                         },
                                                         vpc=vpc,
                                                         security_groups=[order_event_redis_updater_sg],
                                                         vpc_subnets=ec2.SubnetSelection(
                                                             subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                         )

        # add SQS trigger to Order Event Redis Updater
        OrderEventRedisUpdater_lambda.add_event_source(event_source.SqsEventSource(sqs_redis_updater_queue))

        OrderReceiver_lambda = lambda_.Function(self, "OrderReceiver",
                                                runtime=lambda_.Runtime.PYTHON_3_12,
                                                handler="lambda_function.lambda_handler",
                                                code=lambda_.Code.from_asset(os.path.join(
                                                    "./lambda-codes/order_receiver.zip")),
                                                role=orderreceiver_role,
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

        OrderEventTablePoller_lambda = lambda_.Function(self, "OrderEventTablePoller",
                                                        runtime=lambda_.Runtime.PYTHON_3_12,
                                                        handler="lambda_function.lambda_handler",
                                                        code=lambda_.Code.from_asset(os.path.join(
                                                            "./lambda-codes/order_event_table_poller.zip")),
                                                        role=ordereventtablepoller_role,
                                                        environment={
                                                            "DB_HOST": cluster.cluster_read_endpoint.hostname,
                                                            "DB_NAME": "orders",
                                                            "DB_PORT": "5432",
                                                            "SECRET_NAME": secret.secret_name,
                                                            "SNS_ARN": order_event_topic.topic_arn
                                                        },
                                                        vpc=vpc,
                                                        security_groups=[order_events_table_poller_lambda_sg],
                                                        vpc_subnets=ec2.SubnetSelection(
                                                            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                        )

        OrderEventTableCleaner_lambda = lambda_.Function(self, "OrderEventTableCleaner",
                                                         runtime=lambda_.Runtime.PYTHON_3_12,
                                                         handler="lambda_function.lambda_handler",
                                                         code=lambda_.Code.from_asset(os.path.join(
                                                             "./lambda-codes/order_event_table_cleaner.zip")),
                                                         role=ordereventtablecleaner_role,
                                                         environment={
                                                             "DB_HOST": cluster.cluster_endpoint.hostname,
                                                             "DB_NAME": "orders",
                                                             "DB_PORT": "5432",
                                                             "SECRET_NAME": secret.secret_name
                                                         },
                                                         vpc=vpc,
                                                         security_groups=[order_events_table_cleaner_lambda_sg],
                                                         vpc_subnets=ec2.SubnetSelection(
                                                             subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                                                         )
        OrderEventTableCleaner_lambda.add_event_source(event_source.SqsEventSource(order_event_table_cleaner_queue))

        # Granting permitions to Order Receiver lambda access RDS and Secret Manager
        cluster.grant_connect(OrderReceiver_lambda, "AdminDBUser")
        cluster.grant_connect(OrderEventTablePoller_lambda, "AdminDBUser")
        cluster.grant_connect(OrderEventTableCleaner_lambda, "AdminDBUser")
        secret.grant_read(OrderReceiver_lambda)
        secret.grant_read(OrderEventTablePoller_lambda)
        secret.grant_read(OrderEventTableCleaner_lambda)

        ordereventtablepollerscheduler_role = iam.Role(self, "OrderEventTablePollerSchedule_role",
                                        assumed_by=iam.ServicePrincipal("scheduler.amazonaws.com"))
        ordereventtablepollerscheduler_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        ordereventtablepollerscheduler_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[OrderEventTablePoller_lambda.function_arn]
            )
        )

        OrderEventTableExecRule = events.Rule(self,
                                              "OrderEventTableExecRule",
                                              enabled=True,
                                              schedule=events.Schedule.rate(aws_cdk.Duration.minutes(1)),
                                              rule_name="OrderEventTableExecRule",
                                              description="Rule to startup the lambda that will update the SNS topic and send to Elasticache Cluster"
                                              )

        OrderEventTableExecRule.add_target(targets.LambdaFunction(OrderEventTablePoller_lambda,
                                                                  max_event_age=aws_cdk.Duration.hours(1),
                                                                  retry_attempts=4))

        OrderEventTableExecRule.node.add_metadata("uniqueId", "startup")
        OrderEventTableExecRule.node.add_dependency(OrderEventTablePoller_lambda)

        ClientRetriever_lambda = lambda_.Function(self, "ClientRetriever",
                                                  runtime=lambda_.Runtime.PYTHON_3_12,
                                                  handler="lambda_function.lambda_handler",
                                                  code=lambda_.Code.from_asset(os.path.join(
                                                      "./lambda-codes/client_retriever.zip")),
                                                  role=clientretriever_role,
                                                  environment={
                                                      "REDIS_HOST": redis_cluster.attr_redis_endpoint_address,
                                                      "REDIS_PORT": "6379"
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
