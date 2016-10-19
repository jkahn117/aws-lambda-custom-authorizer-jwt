#
# Lambda function that acts as a Custom Authorizer for API Gateway.  Checks
# a provided JWT token, verifies signature, and authorizes access against
# the requested resource before providing policy to allow or deny access.
#

'use strict'
require('dotenv').config()

#
# Regular expression to extract JWT token from Authorization header.
#
BEARER_TOKEN_PATTERN = /^Bearer\s+([^\s]+)\s*$/i;

#
# Main handler function for Lambda. Extracts JWT authorization token from
# header and resource from method ARN before passing to the JWTAuthorizer
# class to authorize access.
#
exports.handler = (event, context) ->
  token  = BEARER_TOKEN_PATTERN.exec(event.authorizationToken)[1]

  authorizer = new JWTAuthorizer(token)
  authorizer.isAuthorizedFor event.methodArn, (principalId, status, error) =>
    switch status
      # Authenticated and authorized to access method
      when AuthorizerStatus.OK
        console.log("OK response for #{principalId} : #{event.methodArn}")
        policy = new SimplePolicy(principalId, event.methodArn, 'Allow')
        context.succeed policy.build()

      # Authenticated but not authorized to access method
      when AuthorizerStatus.FORBIDDEN
        console.log("FORBIDDEN response for #{principalId} : #{event.methodArn}")
        policy = new SimplePolicy(principalId, event.methodArn, 'Deny')
        context.succeed policy.build()

      # Not authenticated to access method (unknown user)
      when AuthorizerStatus.UNAUTHORIZED
        console.log("UNAUTHORIZED response for #{principalId}")
        context.fail("Unauthorized")

      # Error occurred in processing or JWT verification
      else
        console.log("[ERROR] #{error}")
        context.fail("Internal Server Error")

