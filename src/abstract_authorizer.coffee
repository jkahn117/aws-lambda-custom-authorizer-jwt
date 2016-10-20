#
# Abstract authorizer class that provides common methods for checking
# access to a method (based on ARN) for a given principal id. This
# authorizer works against a simple DynamoDB table to check if a
# principalID exists in the table as well as if that user has access
# to the given resource (using API identifier + stage + HTTP method).
#

AWS = require('aws-sdk')
AWS.config.update { region: 'us-west-2' }

#
# Enumeration of status codes for internal authorizer status.
#
AuthorizerStatus =
  OK:             1  # authorized user, allow to service
  FORBIDDEN:      2  # authorized user, deny to service
  UNAUTHORIZED:   3  # not an authorized user
  JWT_ERROR:      4  # error in decoding JSON Web Token
  INTERNAL_ERROR: 5  # some other server error

class AbstractAuthorizer
  #
  # Constructor.
  #
  # @param {String} token
  #
  constructor: (@token) ->
    # nothing more to do here

  #
  # Tests if the token provided to this instance represents an authenticated
  # user with access to the passed resource.  Returns result as callback.
  #
  # @param {String} resource: method ARN
  # @param {Function} callback(AuthorizerStatus): called with result
  #
  isAuthorizedFor:(resource, callback) ->
    throw Error 'Method #isAuthorizedFor should be implemented by subclass'

  #
  # Verify token.
  #
  # @param {Function} callback (decodedValue, AuthorizerStatus, errorMessage)
  #
  _verify:(callback) ->
    throw Error 'Method #_verify should be implemented by subclass'

  #
  # Tests if the authenticated user (identified by principal id) is authorized
  # to access the passed resource. (Private)
  #
  # @param {String} principalId: identifier for user
  # @param {String} resource: ARN for resource to access
  # @param {Function} callback(principalId, AuthorizerStatus, error)
  #
  _authorizedForResource:(principalId, resource, callback) ->
    params =
      Key:
        resource:
          S: @_extractResource(resource)
        username:
          S: principalId
      TableName: process.env.TABLE_NAME
      ProjectionExpression: 'httpMethod'

    ddb = new AWS.DynamoDB { apiVersion: '2012-08-10' }
    ddb.getItem params, (error, data) =>
      if error
        callback(principalId, AuthorizerStatus.INTERNAL_ERROR, error.message)
      else
        if data.Item && data.Item.httpMethod
          allowedMethod = data.Item.httpMethod.S
          if allowedMethod == '*' || allowedMethod == @_extractMethod(resource)
            callback(principalId, AuthorizerStatus.OK, null)
          else
            callback(principalId, AuthorizerStatus.FORBIDDEN, null)
        else
          callback(principalId, AuthorizerStatus.UNAUTHORIZED, null)

  #
  # Extracts the resource identifier (API id + stage) from the passed ARN.
  #
  # Example: arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/GET/
  #
  # @param {String} arn
  # @return {String} resource identifier
  #
  _extractResource:(arn) ->
    aelems = arn.split(':', 6)
    relems = aelems[5].split('/', 4)
    "#{relems[0]}/#{relems[1]}"

  #
  # Extracts the HTTP method (e.g. GET, PUT) from the passed ARN.
  #
  # Example: arn:aws:execute-api:us-west-2:123456789012:ymy8tbxw7b/*/GET/
  #
  # @param {String} arn
  # @return {String} http method
  #
  _extractMethod:(arn) ->
    aelems = arn.split(':', 6)
    relems = aelems[5].split('/', 4)
    relems[2]

