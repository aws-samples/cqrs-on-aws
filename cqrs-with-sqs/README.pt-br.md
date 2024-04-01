[![en](https://img.shields.io/badge/lang-en-red.svg)](https://github.com/aws-samples/cqrs-on-aws/blob/main/cqrs-with-sqs/README.md)

# CQRS na AWS: sincronizando serviços de comando e consulta com o Amazon SQS

Esta parte descreve como ter a infraestrutura explorada na postagem do blog [CQRS na AWS: Sincronizando os Serviços de
Command e Query com o Amazon SQS](https://aws.amazon.com/pt/blogs/aws-brasil/cqrs-na-aws-sincronizando-os-servicos-de-command-e-query-com-o-amazon-sqs)
implantada em sua conta da AWS. Nessa abordagem, sincronizamos os serviços de comando e consulta publicando eventos em
uma fila do Amazon SQS a partir do serviço de comando a ser consumido pelo serviço de consulta.

## Executando o código para implantar a infraestrutura de sua máquina local

Para executar o código da infraestrutura que você deseja implantar em sua conta da AWS, antes de executar o código do AWS
CDK, é necessário ter o gerenciador de pacotes NPM, o AWS CLI, o AWS CDK CLI e a linguagem de programação Python. Se você
ainda não tiver o gerenciador de pacotes npm instalado, siga as instruções na página [Baixando e instalando Node.js e npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).
Para instalar a AWS CLI, siga as instruções na página [Instalar ou atualizar para a versão mais recente da AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
Para instalar a CLI do AWS CDK, siga as instruções na página [AWS CDK Toolkit](https://docs.aws.amazon.com/cdk/v2/guide/cli.html).
E, finalmente, para instalar a linguagem de programação Python, siga as instruções na [Página de downloads do Python](https://www.python.org/downloads).
Para que a infraestrutura seja implantada em sua conta da AWS por meio de sua máquina local, certifique-se de que todos os pré-requisitos sejam executados. Depois disso, siga as etapas abaixo.

1. Clone este repositório Git em sua máquina local.
2. Em um terminal, navegue até o diretório "cqrs-with-sqs".
3. Execute "python3.11 -m venv .venv" (a parte "python3.11" do comando pode variar, dependendo da versão do Python que você tem).
4. Execute "source .venv/bin/activate".
5. Execute "pip install --upgrade pip".
6. Execute "python3.11 -m pip install -r requirements.txt" (a parte "python3.11" do comando pode variar, dependendo da versão do Python que você tem).
7. Na conta na qual a infraestrutura será provisionada, crie um usuário com acesso de administrador e configure as credenciais desse usuário na AWS CLI (ou seja, com [aws configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)). Se as credenciais foram criadas em um perfil da AWS CLI (por exemplo, com aws configure --profile), defina a variável de ambiente AWS_DEFAULT_PROFILE com o nome do perfil criado.
8. Execute "cdk bootstrap".
9. Execute "cdk deploy". Quando a mensagem "Deseja implantar essas mudanças (s/n)? ", digite "y" e pressione enter. Isso criará toda a infraestrutura e levará cerca de 16 minutos.

## Executando o exemplo

Depois de seguir as etapas acima, a mesma infraestrutura descrita na postagem do blog [CQRS na AWS: Sincronizando os
Serviços de Command e Query com o Amazon SQS](https://aws.amazon.com/pt/blogs/aws-brasil/cqrs-na-aws-sincronizando-os-servicos-de-command-e-query-com-o-amazon-sqs)
será provisionada em sua conta da AWS. Isso inclui os bancos de dados e as APIs dos serviços de comando e consulta. Para
executar o exemplo, depois de provisionar a infraestrutura em sua conta da AWS, siga as etapas abaixo.

1. Faça login na sua conta da AWS.
2. Na barra "Pesquisar", digite "API Gateway" e navegue até o primeiro resultado.
3. No menu à esquerda, navegue até "Chaves de API".
4. Na lista de chaves, copie o valor da "chave de API" da chave de API "admin_key". Esse é um valor codificado em base64 e será necessário decodificar esse valor de alguma forma. Após a decodificação, você verá dois valores separados por dois pontos. Esses dois valores são, respectivamente, o nome de usuário e a senha que usaremos para invocar nossas APIs.
5. No menu à esquerda, navegue até "APIs".
6. Na lista de APIs, navegue até o API "OrdersAPI".
7. No menu à esquerda, navegue até "Estágios". O estágio "prod" contém o URI da API provisionada, na seção "Detalhes do estágio", em "Invoke URL". Essa é a API com a qual interagiremos com os serviços de comando e consulta. Copie esse URI. Usaremos essa API para recuperar os detalhes de um cliente e fazer um pedido. Observe que o mesmo valor pode ser recuperado na guia "Saídas" da pilha "CqrsonAWS", na página de serviço do CloudFormation.
8. Faremos um pedido para o cliente #1 emitindo uma solicitação POST para nosso serviço de comando. Para isso, anexaremos "/orders" ao URI que foi copiado anteriormente (por exemplo, https://xyz123.execute-api.us-east-1.amazonaws.com/prod/orders) e emitiremos uma solicitação POST para ele. Se você estiver usando uma ferramenta como o Postman, adicione uma autenticação básica com o nome de usuário e a senha que foram recuperados na etapa #4. O cabeçalho "Content-Type" é "application/json". O corpo da solicitação pode ser o seguinte:
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
Se você estiver usando uma ferramenta como cURL, a solicitação POST terá a seguinte aparência:
```shell
curl -d '{"id_client":1,"products":[{"id_product":1,"quantity":1},{"id_product":2,"quantity":3}]}' -H "Content-Type: application/json" -H "Authorization: Basic <VALUE OF THE API KEY COPIED IN STEP #4 IN BASE64>" -X POST https://xyz123.execute-api.us-east-1.amazonaws.com/prod/orders
```
Depois de configurar a solicitação, emita a solicitação. Você deve ver a seguinte saída:
```json
{
    "statusCode": 200,
    "body": "Order created successfully!"
}
```
9. Agora, verificaremos se o cliente com id #1 foi salvo em nosso serviço de consulta emitindo uma solicitação GET para ele. Para isso, anexaremos "/clients/1" ao URI que foi copiado na etapa #7 (por exemplo, https://xyz123.execute-api.us-east-1.amazonaws.com/prod/clients/1) e emitiremos uma solicitação GET. Se você estiver usando uma ferramenta como o Postman, adicione uma autenticação básica, assim como foi feito na etapa #8. Se você estiver usando uma ferramenta como cURL, a solicitação GET terá a seguinte aparência:
```shell
curl -H "Authorization: Basic <VALUE OF THE API KEY COPIED IN STEP #4 IN BASE64>" https://xyz123.execute-api.us-east-1.amazonaws.com/prod/clients/1
```
Você deve ter uma saída semelhante à seguinte:
```json
{
    "name": "Bob",
    "email": "bob@anemailprovider.com",
    "total": 3000.0,
    "last_purchase": 1707484820
}
```
10. É isso aí! Você configurou os serviços de comando e consulta em sua conta da AWS e emitiu solicitações para ela. Sinta-se à vontade para navegar até a página dos serviços que são explorados na postagem do blog para ver como as coisas estão organizadas.
11. Para remover a infraestrutura que foi provisionada para não incorrer em custos, navegue até a página do serviço CloudFormation, selecione a pilha "CQRSonAWS", clique no botão "Excluir" e confirme.