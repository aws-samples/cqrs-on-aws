[![pt-br](https://img.shields.io/badge/lang-pt--br-green.svg)](README.pt-br.md)<br />
[![es-sp](https://img.shields.io/badge/lang-es--sp-green.svg)](README.es-sp.md)

# CQRS on AWS: Synchronizing Command and Query Services with the Transactional Outbox Pattern, the Transaction Log Tailing Technique and the Debezium Connector

This part describes how to have the infrastructure explored in the blog post [CQRS on AWS: Synchronizing Command and Query Services with the Transactional Outbox Pattern, the Transaction Log Tailing Technique and the Debezium Connector](https://aws.amazon.com/pt/blogs/aws-brasil/cqrs-na-aws-sincronizando-os-servicos-de-command-e-query-com-o-padrao-transactional-outbox-a-tecnica-transaction-log-tailing-e-o-debezium-connector)
deployed in your AWS account. In this approach, we synchronize command and query services using an outbox table. When data
persists in the tables involved in a certain functionality, we also persist a record representing the event related to the
data being persisted (e.g., order was created, payment was authorized, etc.). After inserting an event in Aurora, Debezium
reads the transaction log from the outbox table and publishes the events to an Amazon MSK topic, which is read by an EventBridge
pipe that publishes the events to an SNS topic. SNS then delivers the events in two queues, one of which is read by a Lambda
that updates Redis, with the latest customer data related to each event.

## Running the code to deploy the infrastructure from your local machine

To run the code of the infrastructure you wish to have deployed in your AWS account, prior to running the AWS CDK code,
it is necessary to have the NPM package manager, the AWS CLI, the AWS CDK CLI and the Python programming language. If you
still don't have the npm package manager installed, please follow the instructions in the [Downloading and Installing Node.js and npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
page. To install the AWS CLI, please follow the instructions in the [Install or update to the latest version of the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
page. To install the AWS CDK CLI, please follow the instructions in the [AWS CDK Toolkit](https://docs.aws.amazon.com/cdk/v2/guide/cli.html)
page. And finally, to install the Python programming language, please follow the instructions at the [Python Downloads Page](https://www.python.org/downloads).

To have the infrastructure deployed in your AWS account by deploying it from your local machine, please make sure all
prerequisites are executed. After that, please follow the steps bellow.

1. Clone this Git repository to your local machine.
2. On a terminal, navigate to the "cqrs-with-transactional-outbox-tlt-debezium" directory.
3. Run "python3.12 -m venv .venv" (the "python3.12" part of the command may vary, depending on the version of Python that you have).
4. Run "source .venv/bin/activate".
5. Run "pip install --upgrade pip".
6. Run "python3.12 -m pip install -r requirements.txt" (the "python3.12" part of the command may vary, depending on the version of Python that you have).
7. In the account in which the infrastructure will be provisioned, create a user with admin access and configure the credentials of this user in the AWS CLI (i.e., with [aws configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)). If the credentials were created in an AWS CLI profile (e.g., with aws configure --profile), set the AWS_DEFAULT_PROFILE environment variable to the name of the created profile. 
8. Run "cdk synth".
9. Run "cdk deploy". When the message "Do you wish to deploy these changes (y/n)?" shows up, type "y" and hit enter. This will create the entire infrastructure, and will take around 1 hour and 15 minutes.

## Running the example

After following the steps above, the exact same infrastructure as described in the [CQRS on AWS: Synchronizing Command and Query Services with the Transactional Outbox Pattern, the Transaction Log Tailing Technique and the Debezium Connector](https://aws.amazon.com/pt/blogs/aws-brasil/cqrs-na-aws-sincronizando-os-servicos-de-command-e-query-com-o-padrao-transactional-outbox-a-tecnica-transaction-log-tailing-e-o-debezium-connector)
blog post will be provisioned in your AWS account. This includes the databases and APIs of both the command and query services.

To run the example, after provisioning the infrastructure in your AWS account, please follow the steps bellow.

1. Log in to your AWS account.
2. In the search bar, type "API Gateway" and navigate to the first result.
3. On the left menu, navigate to "API keys".
4. In the list of keys, copy the "API key" value of the "admin_key" API key. This is a base64-encoded value, and it will be necessary to somehow decode this value (such as using an online tool, or the "base64" Linux command). After decoding, you'll see two values separated by colon. These two values are respectively the username and the password we'll use to invoke our APIs. 
5. On the left menu, navigate to "APIs".
6. In the list of APIs, navigate to the "OrdersAPI" API.
7. In the left menu, navigate to "Stages". The "prod" stage contains the URI of the provisioned API, in the "Stage details" section, under "Invoke URL". This is the API with which we will interact with both command and query services. Copy this URI. We'll use this API to retrieve a client's details as well as place an order. Note that the same value can be retrieved from the "Outputs" tab of the "cqrsOnAws" stack, in the CloudFormation service page.
8. We'll place an order for client #1 by issuing a POST request to our command service. For such, we'll append "/orders" to the URI that was previously copied (e.g., https://xyz123.execute-api.us-east-1.amazonaws.com/prod/orders) and issue a POST request to it. If you're using a tool such as Postman, add a basic authentication with the username and password that were retrieved in step #4. The "Content-Type" header is "application/json". The body of the request can be the following:
```json
{
    "id_client": 1,
    "products": [{
         "id_product": 1,
         "quantity": 1
    }, {
         "id_product": 2,
         "quantity": 3
    }]
}
```
If you're using a tool such as cURL, the POST request will look like the following:
```shell
curl -d '{"id_client":1,"products":[{"id_product":1,"quantity":1},{"id_product":2,"quantity":3}]}' -H "Content-Type: application/json" -H "Authorization: Basic <value of the api key copied in step #4 in base64>" -X POST https://xyz123.execute-api.us-east-1.amazonaws.com/prod/orders
```
Issue this request. You should see the following output:
```json
{
    "statusCode": 200,
    "body": "Order created successfully!"
}
```
9. Now, we'll verify if the client with id #1 was saved in our query service by issuing a GET request to it. For such, we'll append "/clients/1" to the URI that was copied in step #7 (e.g., https://xyz123.execute-api.us-east-1.amazonaws.com/prod/clients/1) and issue a GET request. If you're using a tool such as Postman, add a basic authentication, just as was done in step #8. If you're using a tool such as cURL, the GET request will look like the following:
```shell
curl -H "Authorization: Basic <VALUE OF THE API KEY COPIED IN STEP #4 IN BASE64>" https://xyz123.execute-api.us-east-1.amazonaws.com/prod/clients/1
```
Because the table records are retrieved from time to time (every 1 minute, in the case of this example), it will be necessary to wait for the next minute. After waiting, issue the request. You should have an output similar to the following:
```json
{
    "name": "Bob",
    "email": "bob@anemailprovider.com",
    "total": 3000.0,
    "last_purchase": 1707484820
}
```
10. That's it! You've setup both command and query services in your AWS account and issued requests to it. Feel free to navigate to the page of the services that are explored in the blog post to see how things are arranged.
11. To remove the infrastructure that was provisioned to not incur any costs, a few steps are required. Because the infrastructure created is relatively complex and some resources have to be created after the creation of the initial infrastructure, in order to clean the resources, it will be necessary to follow some steps. To delete the created infrastructure, in the console, go to Amazon MSK. Then, in MSK Connect, go to "Connectors", select the "KafkaOrderEventConnector" connector and delete it. Then, go to "Custom plugins", select the "debezium-plugin" plugin and delete it. Then, go to Amazon CloudFormation, Stacks, and click the radio button from the "cqrsOnAws" stack. Delete the stack. This deletion will take approximately 30 minutes. It probably won't be possible to delete the entire stack. If this happens, go to Amazon EC2 and, under "Network & Security", go to "Network Interfaces". Delete the two remaining interfaces by selecting them and clicking "Delete" in the "Actions" menu. Then go back to CloudFormation, select the "cqrsOnAws" stack and click "Retry Delete". Then choose "Force delete this entire stack" and click "Delete".