import json
from jwt import check_scope_lambda

@check_scope_lambda(required_scope='access:external')
def test_lambda(event, context):
    print('Hello')

with open('http_apigw_event.json', 'rb') as f:
    event = json.load(f)
    test_lambda(event, {})

with open('rest_apigw_event.json', 'rb') as f:
    event = json.load(f)
    test_lambda(event, {})