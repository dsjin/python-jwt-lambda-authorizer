import re
import json
from jose import jwt
from six.moves.urllib.request import urlopen

BASE_JWSK_URL = 'https://{tenant_url}/.well-known/jwks.json'
PATTERN = re.compile(r'^Bearer (.*)$')

class RSAKeyNotFoundError(Exception):
    pass

class AuthError(Exception):
    def __init__(self, error):
        self.error = error

class TokenError(Exception):
    def __init__(self, error):
        self.error = error

class JWKSClient:

    _jwks = None

    def __init__(
        self,
        tenant_url: str,
        audience: str,
        issuer: str
    ):
        self.audience = audience
        self.issuer = issuer
        self.tenant_url = tenant_url
        self.jwks_url = BASE_JWSK_URL.format(
            tenant_url=tenant_url
        )
        self._jwks = self.get_jwks()
    
    def get_jwks(self, force: bool = False):
        try:
            if not self._jwks or force:
                print(self.jwks_url)
                jsonurl = urlopen(self.jwks_url)
                self._jwks = json.loads(jsonurl.read())
            return self._jwks
        except Exception as e:
            raise e

class JWT:
    
    _rsa_key = None
    verified = False
    decoded = None

    def __init__(
        self,
        audience: str,
        issuer: str,
        token: str,
        jwks_client: object
    ):
        self.audience = audience
        self.issuer = issuer
        self.token = token
        self.jwks_client = jwks_client
        self.decoded = self._verify()
        self._rsa_key = self.get_rsa_key()

    def get_rsa_key(self, attempt: bool = True):
        def _get_key_from_jwks(jwks: dict, header: dict):
            target_rsa_key = list(map(lambda key: {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }, filter(lambda key: key['kid'] == header['kid'], jwks['keys'])))
            return target_rsa_key[0] if target_rsa_key else None
        try:
            unverified_header = jwt.get_unverified_header(self.token)
            if not self._rsa_key:
                target_rsa_key = _get_key_from_jwks(self.jwks_client.get_jwks(), unverified_header)
                if not target_rsa_key and attempt:
                    self.jwks_client.get_jwks(force=True)
                    target_rsa_key = self.get_rsa_key(attempt=False)
                if not target_rsa_key:
                    raise RSAKeyNotFoundError('RSA Key not found in the jwks keys')
                self._rsa_key = target_rsa_key
            return self._rsa_key
        except Exception as e:
            raise e

    def _verify(self):
        target_rsa_key = self.get_rsa_key()
        if target_rsa_key:
            try:
                payload = jwt.decode(
                    self.token,
                    target_rsa_key,
                    algorithms=["RS256"],
                    audience=self.audience,
                    issuer=self.issuer
                )
                return payload
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"})
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    "please check the audience and issuer"})
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."})
        else:
            raise RSAKeyNotFoundError('RSA Key not found in the jwks keys')

    @staticmethod
    def get_token(param: dict):
        if not param['type'] or param['type'] != 'TOKEN':
            raise TokenError('Expected "event.type" parameter to have value "TOKEN"')
        elif not param['authorizationToken']:
            raise TokenError('Expected "event.authorizationToken" parameter to be set')
        match = PATTERN.match(param['authorizationToken'])
        if not match:
            raise TokenError('Invalid Authorization token - {token_string} does not match "Bearer .*"'.format(token_string = param['authorizationToken']))
        
        return match[1]

    @staticmethod
    def check_scope(token: str, required_scope: str) -> bool:
        unverified_claims = jwt.get_unverified_claims(token)
        if unverified_claims.get("scope"):
            token_scopes = unverified_claims["scope"].split()
            for token_scope in token_scopes:
                if token_scope == required_scope:
                    return True
        return False

def check_scope_lambda(required_scope: str):
    def decorator(func):
        def inner(event, context):
            target_token = JWT.get_token(event)
            is_valid = JWT.check_scope(target_token, required_scope)
            if not is_valid:
                raise TokenError('Insufficient Scope: Require {scope}'.format(scope=required_scope))
            return func(event, context)
        return inner
    return decorator