import os
from jwt import JWKSClient, JWT

allowed_resources = os.environ.get('allowed_resources', []).split(' ')

jwks_client = JWKSClient(
    tenant_url=os.environ.get('tenant_url', 'tenant_url')
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
            audience=os.environ.get('audience', 'audience'),
            issuer=os.environ.get('issuer', 'issuer'),
            token=JWT.get_token_request(event),
            jwks_client=jwks_client
        )
        return {
            'principalId': jwt_instance.decoded['sub'],
            'policyDocument': get_policy_document('Allow', allowed_resources),
            'context': {
                **format_payload(jwt_instance.decoded)
            }
        }
    except Exception as e:
        print(e)
        raise Exception("Unauthorized")

