try:
    basestring
except NameError:  # Python 3
    basestring = str
import calendar
import jwt
import datetime
import time

from jwt.contrib.algorithms.pycrypto import RSAAlgorithm


jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))

__all__ = ['create_token']


def create_token(service_account_email, private_key, uid, claims=None):
    """
    Generates a secure authentication token.

    Our token format follows the JSON Web Token (JWT) standard:
    header.claims.signature

    Where:
    1) "header" is a stringified, base64-encoded JSON object containing version and algorithm information.
    2) "claims" is a stringified, base64-encoded JSON object containing a set of claims.
    3) A signature that proves the validity of this token (see: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-07)

    For base64-encoding we use URL-safe base64 encoding. This ensures that the entire token is URL-safe
    and could, for instance, be placed as a query argument without any encoding (and this is what the JWT spec requires).

    Args:
        service_account_email - the Firebase project's service account email address
        private_key - the Firebase project's PEM encoded private key
        uid - the user ID that is authenticated by the generated token
        claims - additional claims to include in the token payload
    Returns:
        A signed Firebase Authentication Token
    Raises:
        ValueError: if any argument is invalid, or a forbidden claim is found in claims.

    """
    if claims is None:
        claims = {}

    if not isinstance(service_account_email, basestring):
        raise ValueError("firebase_token_generator.create_token: service_account_email must be a string.")

    if not isinstance(private_key, basestring):
        raise ValueError("firebase_token_generator.create_token: private_key must be a string.")

    if not isinstance(uid, basestring):
        raise ValueError("firebase_token_generator.create_token: uid must be a string.")

    if len(uid) > 256:
        raise ValueError("firebase_token_generator.create_token: uid must not be longer than 256 bytes.")

    _validate_claims(claims)
    claims = _create_claims_v3(service_account_email, uid, claims)

    token = jwt.encode(claims, private_key, algorithm='RS256').decode('utf8')

    if len(token) > 7168:
        raise RuntimeError("firebase_token_generator.create_token: generated token is too long.")

    return token


def _validate_claims(data):
    forbidden = ['acr', 'amr', 'at_hash', 'aud',
                 'auth_time', 'azp', 'cnf', 'c_hash',
                 'exp', 'firebase', 'iat', 'iss',
                 'jti', 'nbf', 'nonce', 'sub']

    for key in forbidden:
        if key in data:
            raise ValueError("firebase_token_generator.create_token: {} not allowed in additional claims.", key)


def _create_claims_v3(service_account_email, uid, additional_claims):
    iat = int(time.time())
    exp = iat + 60 * 60

    return {
        'iss': service_account_email,
        'sub': service_account_email,
        'aud': 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
        'iat': iat,
        'exp': exp,
        'uid': uid,
        'claims': additional_claims
    }
