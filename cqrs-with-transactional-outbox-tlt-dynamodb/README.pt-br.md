[![en](https://img.shields.io/badge/lang-en-green.svg)](README.md)<br />
[![es-sp](https://img.shields.io/badge/lang-es--sp-green.svg)](README.es-sp.md)

# CQRS na AWS: Sincronizando os Serviços de Command e Query com o Padrão Transactional Outbox, a Técnical Transaction Log Tailing e o Amazon DynamoDB Streams

Esta parte descreve como ter a infraestrutura explorada no blog post [CQRS na AWS: Sincronizando os Serviços de
Command e Query com o Padrao Transactional Outbox, a Técnica Transaction Log Tailing e o Amazon DynamoDB Streams](https://aws.amazon.com/pt/blogs/aws-brasil/cqrs-na-aws-sincronizando-os-servicos-de-command-e-query-com-o-padrao-transactional-outbox-a-tecnica-transaction-log-tailing-e-o-amazon-dynamodb-streams)
implantada em sua conta da AWS. Nessa abordagem, sincronizamos os serviços de comandos e consultas usando uma outbox table.
Embora estejamos usando a abordagem [Single Table Design](https://aws.amazon.com/blogs/compute/creating-a-single-table-design-with-amazon-dynamodb),
ainda estamos persistindo um evento junto com outros dados em nossa tabela do Amazon DynamoDB, que é consumido posteriormente
por meio de um Amazon DynamoDB Streams. Não é possível usar uma ferramenta como o Debezium para ler o log de transações
de uma tabela do Amazon DynamoDB, mas o serviço em si fornece um recurso para acompanhar o log de transações da tabela,
que é o Amazon DynamoDB Streams. Depois de inserir todos os dados envolvidos no recebimento de um pedido, também inserimos
um evento que representa a realização do pedido, e esse evento é disponibilizado em um stream do Amazon DynamoDB, que é
lido por um pipe do EventBridge, que publica os eventos em um tópico do SNS. O SNS então entrega os eventos em duas filas,
uma das quais é lida por um Lambda que atualiza o banco de dados Aurora, com os dados mais recentes do cliente relacionados
a cada evento.

## Executando o código para implantar a infraestrutura a partir da máquina local

Para executar o código da infraestrutura que você deseja implantar em sua conta da AWS, antes de executar o código do AWS
CDK, é necessário ter o gerenciador de pacotes NPM, o AWS CLI, o AWS CDK CLI e a linguagem de programação Python. Se você
ainda não tiver o gerenciador de pacotes npm instalado, siga as instruções na página [Baixando e instalando Node.js e npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).
Para instalar a AWS CLI, siga as instruções na página [Instalar ou atualizar para a versão mais recente da AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
Para instalar a CLI do AWS CDK, siga as instruções na página [AWS CDK Toolkit](https://docs.aws.amazon.com/cdk/v2/guide/cli.html).
E, finalmente, para instalar a linguagem de programação Python, siga as instruções na [Página de downloads do Python](https://www.python.org/downloads).
Para que a infraestrutura seja implantada em sua conta da AWS a partir da sua máquina local, certifique-se de que todos os
pré-requisitos sejam executados. Depois disso, siga as etapas abaixo.

1. Clone este repositório Git em sua máquina local.
2. Em um terminal, navegue até o diretório "cqrs-with-transactional-outbox-tlt-dynamodb" directory".
3. Execute "python3.12 -m venv .venv" (a parte "python3.12" do comando pode variar, dependendo da versão do Python que você tenha).
4. Execute "source .venv/bin/activate".
5. Execute "pip install --upgrade pip".
6. Execute "python3.12 -m pip install -r requirements.txt" (a parte "python3.12" do comando pode variar, dependendo da versão do Python que você tenha).
7. Na conta na qual a infraestrutura será provisionada, crie um usuário com acesso de administrador e configure as credenciais desse usuário na AWS CLI (ou seja, com [aws configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)). Se as credenciais foram criadas em um perfil da AWS CLI (por exemplo, com aws configure --profile), defina a variável de ambiente AWS_DEFAULT_PROFILE com o nome do perfil criado.
8. Execute "cdk synth".
9. Execute "cdk deploy". Quando a mensagem "Do you wish to deploy these changes (y/n)?" aparecer, digite "y" e pressione enter. Isso criará toda a infraestrutura e levará cerca de 16 minutos.

## Executando o exemplo

Depois de seguir as etapas acima, a mesma infraestrutura descrita na postagem do blog [CQRS na AWS: Sincronizando os Serviços de
Command e Query com o Padrao Transactional Outbox, a Técnica Transaction Log Tailing e o Amazon DynamoDB Streams](https://aws.amazon.com/pt/blogs/aws-brasil/cqrs-na-aws-sincronizando-os-servicos-de-command-e-query-com-o-padrao-transactional-outbox-a-tecnica-transaction-log-tailing-e-o-amazon-dynamodb-streams)
será provisionada em sua conta da AWS. Isso inclui os bancos de dados e as APIs dos serviços de comandos e consulta. Para
executar o exemplo, depois de provisionar a infraestrutura em sua conta da AWS, siga as etapas abaixo.

1. Faça login na sua conta da AWS.
2. Na barra de pesquisa, digite "API Gateway" e navegue até o primeiro resultado.
3. No menu à esquerda, navegue até "API keys".
4. Na lista de chaves, copie o valor da chave de API "admin_key". Esse é um valor codificado em base64 e será necessário decodificar esse valor de alguma forma (por exemplo, utilizando alguma ferramenta online, ou o próprio comando "base64" do Linux). Após a decodificação, você verá dois valores separados por ":". Esses dois valores são, respectivamente, o nome de usuário e a senha que usaremos para invocar nossas APIs.
5. No menu à esquerda, navegue até "APIs".
6. Na lista de APIs, navegue até o API "OrdersAPI".
7. No menu à esquerda, navegue até "Stages". A stage "prod" contém o URI da API provisionada, na seção "Stage details", em "Invoke URL". Essa é a API que utilizaremos para interagir com os serviços de comando e consulta. Copie esse URI. Usaremos essa API para recuperar os detalhes de um cliente e fazer um pedido. Observe que o mesmo valor pode ser recuperado na guia "Outputs" da stack "cqrsOnAws", na página de serviço do CloudFormation.
8. Faremos um pedido para o cliente #1 emitindo uma solicitação POST para nosso serviço de comando. Para isso, anexaremos "/orders" à URI que foi copiada anteriormente (por exemplo, https://xyz123.execute-api.us-east-1.amazonaws.com/prod/orders) e emitiremos uma solicitação POST para ela. Se você estiver usando uma ferramenta como o Postman, adicione uma basic authentication com o nome de usuário e a senha que foram recuperados na etapa #4. O valor do header "Content-Type" é "application/json". O corpo da solicitação pode ser o seguinte:
```json
{
    "client": "bob",
    "products": [{
         "product": "Computer",
         "quantity": 1
    }, {
         "product": "Phone",
         "quantity": 3
    }]
}
```
Se você estiver usando uma ferramenta como cURL, a solicitação POST terá a seguinte aparência:
```shell
curl -d '{"client":"bob","products":[{"product":"Computer","quantity":1},{"product":"Phone","quantity":3}]}' -H "Content-Type: application/json" -H "Authorization: Basic <valor da chave de API copiada no passo #4 em base64>" -X POST https://xyz123.execute-api.us-east-1.amazonaws.com/prod/orders
```
Emita essa solicitação. Você deverá ver a seguinte saída:
```json
{
    "statusCode": 200,
    "body": "Order created successfully!"
}
```
9. Agora, verificaremos se os dados do cliente com id #1 foram salvos em nosso serviço de consulta emitindo uma solicitação GET para ele. Para isso, anexaremos "/clients/bob" à URI que foi copiada na etapa #7 (por exemplo, https://xyz123.execute-api.us-east-1.amazonaws.com/prod/clients/bob) e emitiremos uma solicitação GET. Se você estiver usando uma ferramenta como o Postman, adicione basic authentication, assim como foi feito na etapa #8. Se você estiver usando uma ferramenta como cURL, a solicitação GET terá a seguinte aparência:
```shell
curl -H "Authorization: Basic <valor da chave de API copiada no passo #4 em base64>" https://xyz123.execute-api.us-east-1.amazonaws.com/prod/clients/bob
```
Emita a requisição. Você deve ter uma saída semelhante à seguinte:
```json
{
    "name": "bob",
    "email": "bob@anemailprovider.com",
    "total": 3000.0,
    "last_purchase": 1707484820
}
```
10. É isso aí! Você configurou os serviços de comando e consulta em sua conta da AWS e emitiu solicitações para eles. Sinta-se à vontade para navegar até a página dos serviços que são explorados no blog post para ver como as coisas estão organizadas.
11. Para remover a infraestrutura que foi provisionada para não incorrer em custos, navegue até a página do serviço CloudFormation, selecione a stack "cqrsOnAws", clique no botão "Delete" e confirme.