import boto3
import settings
import base64
import six
import struct
import urllib3
import json
import jwt

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

client = boto3.client('cognito-idp', region_name='us-east-1')
clientID = settings.COGNITO_CLIENT_ID
poolID = settings.COGNITO_POOL_ID


def intarr2long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)

def base64_to_long(data):
    if isinstance(data, six.text_type):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return intarr2long(struct.unpack('%sB' % len(_d), _d))

def jwk_to_pem(jwk):
    exponent = base64_to_long(jwk['e'])
    modulus = base64_to_long(jwk['n'])
    numbers = RSAPublicNumbers(exponent, modulus)
    public_key = numbers.public_key(backend=default_backend())
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def check_pems(pems, token):
    try:
        #verify token attributes
        decoded_jwt = jwt.decode(token,verify=False)

        #fail if token not jwt
        if not decoded_jwt:
            return False

        iss = decoded_jwt.get('iss')

        #fail if the token not from user pool
        if iss != 'https://cognito-idp.us-west-2.amazonaws.com/' + poolID:
            return False

        token_use = decoded_jwt.get('token_use')

        #fail if not access token
        if token_use != 'access':
            return False

        header = jwt.get_unverified_header(token)
        kid = header.get('kid')

        pem = pems.get(kid)

        if not pem:
            return False

        #now verify token signature
        jwt.decode(token,key=pem,verify=True)
        return True

    except Exception as e:
        return False

def valid_token_manual(token):
    #download jwks and save them in pem format
    http = urllib3.PoolManager()
    try:
        url = 'https://cognito-idp.us-west-2.amazonaws.com/' + poolID + '/.well-known/jwks.json'
        r = http.request('GET', url)
        keys = json.loads(r.data)
        pems = dict()
        for key in keys.get('keys'):
            key_id = key.get('kid')
            modulus = key.get('n')
            exponent = key.get('e')
            key_type = key.get('kty')
            jwk = dict(kty=key_type,n=modulus,e=exponent)
            pem = jwk_to_pem(jwk)
            pems[key_id] = pem

        result = check_pems(pems, token)
        return result
    except Exception as e:
        print e
        return False

def valid_token(access_token):
    try:
        response = client.get_user(AccessToken=access_token)
        status = response.get('ResponseMetadata').get('HTTPStatusCode')
        return status
    except:
        return None

def logout(access_token):
    try:
        response = client.global_sign_out(AccessToken=access_token)
        status = response.get('ResponseMetadata').get('HTTPStatusCode')
        return status
    except Exception as e:
        return None

def refresh_tokens(refresh_token):
    try:
        response = client.admin_initiate_auth(
            UserPoolId=poolID,
            AuthFlow='REFRESH_TOKEN_AUTH',
            AuthParameters={
                'REFRESH_TOKEN': refresh_token
            },
            ClientId=clientID,
        )

    except Exception as e:
        print(e)
        return None, None

    identity_token = response.get("AuthenticationResult", None).get("IdToken", None)
    access_token = response.get("AuthenticationResult", None).get("AccessToken", None)

    return identity_token, access_token



def authenticate_user(username, password):
    try:
        response = client.admin_initiate_auth(
            UserPoolId=poolID,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
            },
            ClientId=clientID,
        )

    except Exception as e:
        print(e)
        return False, None, None

    refresh_token = response.get("AuthenticationResult", None).get("RefreshToken", None)
    access_token = response.get("AuthenticationResult", None).get("AccessToken", None)
    id_token = response.get("AuthenticationResult", None).get("IdToken", None)
    return True, refresh_token, access_token, id_token

def sign_up_user(username, password, email):
    # we have to send back some sort of token
    # from this response, that the client can
    # use to confirm the user account.
    try:
        response = client.sign_up(
            ClientId=clientID,
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': email
                }
            ]
        )
    except Exception as e:
        if e.__class__.__name__ == 'ParamValidationError':
            # TODO @anyone, this needs to fail gracefully for the user.
            print(e)
            return False, e

        print(e)
        return False, e

    return True, None

def validate_user_on_aws(username, confirm_code):
    try:
        response = client.confirm_sign_up(
            ClientId=clientID,
            Username=username,
            ConfirmationCode=confirm_code,
            ForceAliasCreation=False
        )
    except Exception as e:
        # print(e)
        return False, e

    return True, None


def admin_confirm_signup(username):
    try:
        response = client.admin_confirm_sign_up(
                    UserPoolId=poolID,
                    Username=username,
        )
    except Exception as e:
        print(e)
        return False

    print(response)
    return True

def admin_delete_user(username):
    # this can only be used as admin delete user,
    # User delete user situation should use Acess key.
    try:
	response = client.admin_delete_user(
			UserPoolId = poolID,
			Username = username,
	)
    except Exception as e:
	print(e)
	return False
    return True

def admin_forgot_password(username):
    # trying to implement forgot_password
    try:
        response = client.forgot_password(
            ClientId=clientID,
            Username=username)
    except Exception as e:
        print(e)
        return False
    return True

def admin_confirm_forgot_password(username, confirmationCode, password):
    # trying to implement forgot_password
    try:
        response = client.confirm_forgot_password(
        ClientId=clientID,
        Username=username,
        ConfirmationCode=confirmationCode,
        Password=password)
    except Exception as e:
        print(e)
        return False
    return True
