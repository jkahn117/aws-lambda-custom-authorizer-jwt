#
# Represents a very simple AWS policy that will allow a resource
# (API Gateway ARN) to be allowed or denied.
#
# TODO: Long term, should make this class more flexible.
#

class SimplePolicy
  constructor:(@principalId, @resource, @effect='Deny') ->
    # nothing more

  build:() ->
    principalId: @principalId,
    policyDocument:
      Version: '2012-10-17',
      Statement: [
        Action:   'execute-api:Invoke',
        Effect:   @effect,
        Resource: @resource
      ]
