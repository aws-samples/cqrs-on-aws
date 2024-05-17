[![en](https://img.shields.io/badge/lang-en-green.svg)](README.md)<br />
[![pt-br](https://img.shields.io/badge/lang-pt--br-green.svg)](README.pt-br.md)

# CQRS en AWS: Sincronizando los Servicios de Command y Query con Amazon SQS

En esta parte se describe cómo implementar en su cuenta de AWS la infraestructura explorada en la entrada del blog [CQRS en AWS: Sincronizando los Servicios de Command y Query con el Estándar Transactional Outbox y la técnica Transaction Log Tailing] (https://aws.amazon.com/pt/blogs/aws-brasil/cqrs-en-aws-sincronizando-los-servicios-de-command-y-query-con-el-estandar-transactional-outbox-y-la-tecnica-polling-publisher).
En este enfoque, sincronizamos los servicios de comandos y consultas mediante una tabla de salida. Cuando los datos
persisten en las tablas relacionadas con una funcionalidad determinada, también conservamos un registro que representa
el evento relacionado con los datos que se conservan (por ejemplo, se creó un pedido, se autorizó el pago, etc.). De vez
en cuando, los registros de la tabla de salida se recuperan y se publican en una cola que es leída por un componente que
actualiza los registros del lado del servicio de consultas.

## Ejecutando el código para implementar la infraestructura desde la máquina local

Para ejecutar el código de infraestructura que desea implementar en su cuenta de AWS, antes de ejecutar el código AWS
CDK, debe tener el administrador de paquetes NPM, la CLI de AWS, la CLI de AWS CDK y el lenguaje de programación Python.
Si aún no tiene instalado el administrador de paquetes npm, siga las instrucciones de la página [Descargar e instalar
Node.js y npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).
Para instalar la CLI de AWS, siga las instrucciones de la página [Instalar o actualizar a la última versión de la CLI de
AWS](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html). Para instalar la CLI de AWS CDK,
siga las instrucciones de la página [AWS CDK Toolkit](https://docs.aws.amazon.com/cdk/v2/guide/cli.html). Por último,
para instalar el lenguaje de programación Python, siga las instrucciones de la [Página de descargas de Python](https://www.python.org/downloads).
Para poder implementar la infraestructura en su cuenta de AWS desde su máquina local, asegúrese de que se cumplen todos
los requisitos previos. Después de eso, siga los pasos que se indican a continuación.

1. Clona este repositorio de Git en tu máquina local.
2. En una terminal, navegue hasta el directorio "cqrs-with-sqs".
3. Ejecute "python3.12 -m venv .venv" (la parte "python3.12" del comando puede variar según la versión de Python que tenga).
4. Ejecute "source .venv/bin/activate".
5. Ejecute "pip install --upgrade pip".
6. Ejecute "python3.12 -m pip install -r requirements.txt" (la parte "python3.12" del comando puede variar según la versión de Python que tenga).
7. En la cuenta en la que se aprovisionará la infraestructura, cree un usuario con acceso de administrador y configure las credenciales de ese usuario en la CLI de AWS (es decir, con [aws configure] (https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)). Si las credenciales se crearon en un perfil de la CLI de AWS (por ejemplo, con aws configure --profile), defina la variable de entorno AWS_DEFAULT_PROFILE con el nombre del perfil creado.
8. Ejecute "cdk synth".
9. Ejecute "cdk deploy". Cuando aparezca el mensaje "Do you wish to deploy these changes (y/n)?" aparezca, escriba "y" y pulse enter. Esto creará toda la infraestructura y tardará unos 16 minutos.

## Executando o exemplo

Tras seguir los pasos anteriores, se aprovisionará en su cuenta de AWS la misma infraestructura descrita en la entrada
del blog [CQRS en AWS: Sincronizando los Servicios de Command y Query con Amazon SQS](https://aws.amazon.com/es/blogs/aws-spanish/cqrs-en-aws-sincronizando-los-servicios-de-command-y-query-con-amazon-sqs).
Esto incluye las bases de datos y las API para los servicios de comandos y consultas. Para ejecutar el ejemplo,
después de aprovisionar la infraestructura en su cuenta de AWS, siga los pasos que se indican a continuación.

1. Inicie sesión en su cuenta de AWS.
2. En la barra de búsqueda, escriba "API Gateway" y navegue hasta el primer resultado.
3. En el menú de la izquierda, navega hasta "API keys".
4. En la lista de claves, copia el valor de la clave de API "admin_key". Se trata de un valor codificado en base64 y será necesario decodificar este valor de alguna manera (por ejemplo, utilizando una herramienta en línea o el comando "base64" propio de Linux). Tras la decodificación, verás dos valores separados por ":". Estos dos valores son, respectivamente, el nombre de usuario y la contraseña que utilizaremos para invocar nuestras API.
5. En el menú de la izquierda, navega hasta "APIs".
6. En la lista de API, navega hasta la API "OrdersAPI".
7. En el menú de la izquierda, navega hasta "Stages". La stage "prod" contiene el URI de la API aprovisionada, en la sección "Stage details", en "Invoke URL". Esta es la API que utilizaremos para interactuar con los servicios de comando y consulta. Copia esa URI. Usaremos esta API para recuperar los detalles de un cliente y realizar un pedido. Tenga en cuenta que se puede recuperar el mismo valor en la pestaña "Outputs" de la pila "cqrsOnAws", en la página del servicio de CloudFormation.
8. Realizaremos un pedido para el cliente #1 emitiendo una solicitud POST a nuestro servicio de comando. Para ello, añadiremos "/orders" al URI que se copió anteriormente (por ejemplo, https://xyz123.execute-api.us-east-1.amazonaws.com/prod/orders) y emitiremos una solicitud POST para ello. Si utilizas una herramienta como Postman, añade la autenticación básica con el nombre de usuario y la contraseña que se recuperaron en el paso #4. El valor del encabezado "Content-Type" es "application/json". El cuerpo de la solicitud puede ser el siguiente:
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
Si utilizas una herramienta como cURL, la solicitud POST tiene el siguiente aspecto:
```shell
curl -d '{"id_client":1,"products":[{"id_product":1,"quantity":1},{"id_product":2,"quantity":3}]}' -H "Content-Type: application/json" -H "Authorization: Basic <El valor de la clave de API se copió en el paso #4 en base64>" -X POST https://xyz123.execute-api.us-east-1.amazonaws.com/prod/orders
```
Emita esta solicitud. Deberías ver el siguiente resultado:
```json
{
    "statusCode": 200,
    "body": "Order created successfully!"
}
```
9. Ahora, verificaremos que los datos del cliente con el identificador #1 se hayan guardado en nuestro servicio de consultas emitiéndole una solicitud GET. Para ello, agregaremos "/clients/1" a la URI que se copió en el paso #7 (por ejemplo, https://xyz123.execute-api.us-east-1.amazonaws.com/prod/clients/1) y emitiremos una solicitud GET. Si utilizas una herramienta como Postman, añade la autenticación básica, tal y como se hizo en el paso #8. Si utilizas una herramienta como cURL, la solicitud GET tiene el siguiente aspecto:
```shell
curl -H "Authorization: Basic <valor de la clave de API se copió en el paso #4 en base64>" https://xyz123.execute-api.us-east-1.amazonaws.com/prod/clients/1
```
Como los registros de la tabla se recuperan de vez en cuando (cada 1 minuto, en el caso de este ejemplo), será necesario esperar al minuto siguiente. Tras esperar, emita la solicitud. Debería tener un resultado similar al siguiente:
```json
{
    "name": "Bob",
    "email": "bob@anemailprovider.com",
    "total": 3000.0,
    "last_purchase": 1707484820
}
```
10. ¡Eso es todo! Ha configurado los servicios de comandos y consultas en su cuenta de AWS y les ha enviado solicitudes. No dude en visitar la página de los servicios que se analizan en la entrada del blog para ver cómo están organizadas las cosas.
11. Para eliminar la infraestructura aprovisionada para no incurrir en costes, vaya a la página de servicio de CloudFormation, seleccione la pila "cqrsOnAws", haga clic en el botón "Delete" y confirme.