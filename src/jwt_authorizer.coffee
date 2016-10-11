#
# Authorizer class to support JSON Web Token (http://jwt.io). Authenticates
# user against user list and then authorizes that user against listing of
# allowed methods.
#

jwt    = require('jsonwebtoken')

class JWTAuthorizer
  #
  # Constructor.
  #
  # @param {String} token
  #
  constructor: (@token) ->
    # nothing more here

  #
  # Tests if the token provided to this instance represents an authenticated
  # user with access to the passed resource.  Returns result as callback.
  #
  # @param {String} resource: e.g. "GET/sales"
  # @param {Function} callback(AuthorizerStatus): called with result
  #
  isAuthorizedFor:(resource, callback) ->
    @_verify (decodedToken, status, error) =>
      if error
        console.log("[ERROR] #{error.message} (#{error.name})")
        callback(error.status, error.message)
      else
        principalId = decodedToken.user
        @_authorizedForResource(principalId, resource, callback)

  #
  # Verify JWT token using shared secret. (Private)
  #
  # @param {Function} callback (decodedValue, AuthorizerStatus, errorMessage)
  #
  _verify:(callback) ->
    jwt.verify(@token, process.env.SECRET, (error, decoded) ->
        if error
          # Handle error in verifying signature, e.g. expired token or JWT error
          callback(null, AuthorizerStatus.JWT_ERROR, error.message)
        else
          callback(decoded, null, null)
      )

  #
  # Tests if the authenticated user (identified by principal id) is authorized
  # to access the passed resource. (Private)
  #
  # @param {String} principalId: identifier for user
  # @param {String} resource: identifier for resource to access
  # @param {Function} callback(principalId, AuthorizerStatus, error)
  #
  _authorizedForResource:(principalId, resource, callback) ->
    # Authenticate the principalId -- this is simple
    if principalId == 'josh'
      # Authorize access to resource -- again, this is a very simplified approach
      if resource == 'GET/sales' || resource == 'GET/'
        callback(principalId, AuthorizerStatus.OK, null)
      else
        callback(principalId, AuthorizerStatus.FORBIDDEN, null)
    else
      callback(principalId, AuthorizerStatus.UNAUTHORIZED, null)
