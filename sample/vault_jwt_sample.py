import base64
import json
import logging
import os
import sys
import time
import uuid
import adal

from azure.keyvault import KeyVaultClient, KeyVaultAuthentication
from azure.common.credentials import ServicePrincipalCredentials
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def turn_on_logging():
    logging.basicConfig(level=logging.DEBUG)
    #or,
    #handler = logging.StreamHandler()
    #adal.set_logging_options({
    #    'level': 'DEBUG',
    #    'handler': handler
    #})

    #handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))

#
# You can provide account information by using a JSON file. Either
# through a command line argument, 'python sample.py parameters.json', or
# specifying in an environment variable of ADAL_SAMPLE_PARAMETERS_FILE.
# privateKeyFile must contain a PEM encoded cert with private key.
# thumbprint must be the thumbprint of the privateKeyFile.
#
# The information inside such file can be obtained via app registration.
# See https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki/Register-your-application-with-Azure-Active-Directory
#
# {
#   tenant: someexample.onmicrosoft.com
#   clientId: 8b34a21c-48da-11e9-8646-d663bd873d93
#   vault_clientId: 9307df90-48da-11e9-8646-d663bd873d93
#   vault_clientSecret: Kdkrkdk+jejedj3j3+djeek+ddjJpC319jd+djwkw===
#   vault_url: https://somekeystore.vault.azure.net
#   cert: somecert
#   cert_thumb: 1F66719C952EB22EDCC9BF99C31940547A38CC22
# }

parameters_file = (sys.argv[1] if len(sys.argv) == 2 else
                   os.environ.get('ADAL_SAMPLE_PARAMETERS_FILE'))
sample_parameters = {}
if parameters_file:
    with open(parameters_file, 'r') as f:
        parameters = f.read()
    sample_parameters = json.loads(parameters)
else:
    raise ValueError('Please provide parameter file with account information.')


def auth_vault_callback(server, resource, scope):
    credentials = ServicePrincipalCredentials(
        client_id=sample_parameters['vault_clientId'],
        secret=sample_parameters['vault_clientSecret'],
        tenant=sample_parameters['tenant'],
        resource='https://vault.azure.net'
    )
    token = credentials.token
    return token['token_type'], token['access_token']


def make_vault_jwt():

    header = {
              'alg': 'RS256',
              'typ': 'JWT',
              'x5t': base64.b64encode(
                        sample_parameters['cert_thumb'].decode('hex'))
             }
    header_b64 = base64.b64encode(json.dumps(header).encode('utf-8'))

    body = {
            'aud': "https://login.microsoftonline.com/%s/oauth2/token" %
                   sample_parameters['tenant'],
            'exp': (int(time.time()) + 600),
            'iss': sample_parameters['clientId'],
            'jti': str(uuid.uuid4()),
            'nbf': int(time.time()),
            'sub': sample_parameters['clientId']
            }
    body_b64 = base64.b64encode(json.dumps(body).encode('utf-8'))

    full_b64 = b'.'.join([header_b64, body_b64])

    client = KeyVaultClient(KeyVaultAuthentication(auth_vault_callback))
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    hasher.update(full_b64)
    digest = hasher.finalize()
    signed_digest = client.sign(sample_parameters['vault_url'],
                                sample_parameters['cert'], '', 'RS256',
                                digest).result

    full_token = b'.'.join([full_b64, base64.b64encode(signed_digest)])

    return full_token


auth_uri = "https://login.microsoftonline.com/%s" % sample_parameters['tenant']
auth_ctx = adal.AuthenticationContext(auth_uri)
token = auth_ctx.acquire_token_with_jwt("https://graph.microsoft.com",
                                        sample_parameters['clientId'],
                                        make_vault_jwt())

print('Here is the token:')
print(json.dumps(token, indent=2))
