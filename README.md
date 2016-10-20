# Amazon API Gateway Custom Authorizer with JSON Web Token

A *sample* implementation of an [Amazon API Gateway Custom Authorizer] (http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html) that makes use of [JSON Web Tokens](http://jwt.io).

## About

API Gateway Custom Authorizers enable you to control access to your APIs utilizing a token authentication strategy, such as JWT, OAuth, or SAML.  Custom Authorizers makes use of a Lambda function to implement the authorization strategy.

In short, when configured to do so, API Gateway will call a Lambda function, passing an authorization token extracted from the client request header.  The function is responsible for verifying the token, authorizing access, and returning an IAM policy that allows or denies access to the API.  API Gateway will cache the returned policy for a configured time-to-live (TTL) up to 3600 seconds.

## Setup and Deploy

This function makes use of a packaging system described (https://medium.com/@joshua.a.kahn/deploying-to-aws-lambda-with-node-js-and-grunt-coffeescript-117df3d1fe73#.35rw5gwpu)[here].  To get started:

1. Clone the repository.
2. Run `npm install` to install required libraries.
3. Move `Gruntfile.coffee.sample` to `Gruntfile.coffee`.
4. Open `.env` file and set a shared secret (see below).
5. Run `grunt package`.
6. Create a new Lambda function via AWS Console, CLI, etc. You can upload a copy of the deployment package from the previous step.
7. Update the AWS Region and Lambda ARN in `Gruntfile.coffee`.  Going forward, you can now deploy updates using `grunt deploy`.
8. Next, we will create a new DynamoDB table, see the subsequent section.

### DynamoDB

As a sample, this function makes use of a simple DynamoDB table to manage authorization to various APIs.  The name of the table is defined in the `.env` file, but is "Authorization" by default.

The "Authorization" table should have three attributes:

* *username* - unique identifier / principal ID for the authorized user
* *resource* - identifier for the API resource, composed of "API_ID/API_STAGE"
* *httpMethod* - standard HTTP method (e.g. GET, POST) or '*' for all methods

You will need to create and populate the table on your own.  The API_ID is available from the API Gateway console.

### Shared Secret

For simplicity, this function makes use of a "shared secret" approach to verify the JWT token.  The passed JWT token must be encoded using the same secret.  One could also make use of PEM encoded private key stored in Amazon KMS.

