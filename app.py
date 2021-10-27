from jwt import JWKSClient, JWT

jwks_client = JWKSClient(
    tenant_url=None,
    audience=None,
    issuer=None
)

get_policy_document = lambda effect, resource: {
    'Version': '2012-10-17',
    'Statement': [{
      'Action': 'execute-api:Invoke',
      'Effect': effect,
      'Resource': resource,
    }]
}

def format_payload(payload: dict) -> dict:
    for key in payload:
        if isinstance(payload[key], list):
            payload[key] = ' '.join(payload[key])
        elif isinstance(payload[key], dict):
            format_payload(payload[key])
    return payload

def lambda_handler(event, context):
    try:
        jwt_instance = JWT(
            audience=None,
            issuer=None,
            token=JWT.get_token(event),
            jwks_client=jwks_client
        )
        return {
            'principalId': jwt_instance.decoded['sub'],
            'policyDocument': get_policy_document('Allow', event['methodArn']),
            'context': {
                'scope': format_payload(jwt_instance.decoded)
            }
        }
    except Exception as e:
        print(e)
        raise Exception("Unauthorized")

