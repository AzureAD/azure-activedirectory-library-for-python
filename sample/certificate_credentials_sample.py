﻿import json
import logging
import os
import sys
import adal

def turn_on_logging():
    logging.basicConfig(level=logging.DEBUG)
    #or, 
    #handler = logging.StreamHandler()
    #adal.set_logging_options({
    #    'level': 'DEBUG',
    #    'handler': handler 
    #})
    #handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))

def get_private_key(filename):
    with open(filename, 'r') as pem_file:
        private_pem = pem_file.read()
    return private_pem

#
# You can provide account information by using a JSON file. Either 
# through a command line argument, 'python sample.js parameters.json', or
# specifying in an environment variable of ADAL_SAMPLE_PARAMETERS_FILE.
# privateKeyFile must contain a PEM encoded cert with private key.
# thumbprint must be the thumbprint of the privateKeyFile.
# {
#   "tenant" : "naturalcauses.onmicrosoft.com",
#   "authorityHostUrl" : "https://login.microsoftonline.com",
#   "clientId" : "d6835713-b745-48d1-bb62-7a8248477d35",
#   "thumbprint" : 'C15DEA8656ADDF67BE8031D85EBDDC5AD6C436E1',
#   "privateKeyFile" : 'ncwebCTKey.pem'
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


authority_url = (sample_parameters['authorityHostUrl'] + '/' + 
                 sample_parameters['tenant'])
RESOURCE = '00000002-0000-0000-c000-000000000000'

#uncomment for verbose logging
turn_on_logging()

context = adal.AuthenticationContext(authority_url)
key = get_private_key(sample_parameters['privateKeyFile'])

token = context.acquire_token_with_client_certificate(
    RESOURCE, 
    sample_parameters['clientId'], 
    key, 
    sample_parameters['thumbprint'])

print('Here is the token:')
print(json.dumps(token, indent=2))
