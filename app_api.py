import os
import json
from jwt import check_scope_lambda, TokenError

required_scope = os.environ.get('required_scope', 'required_scope')

@check_scope_lambda(required_scope=required_scope)
def lambda_handler(event, context):
    # TODO implement
    print(event)
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
