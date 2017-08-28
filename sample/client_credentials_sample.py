import json
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

# You can provide account information by using a JSON file. Either
# through a command line argument, 'python sample.py parameters.json', or
# specifying in an environment variable of ADAL_SAMPLE_PARAMETERS_FILE.
# {
#    "resource": "your_resource",
#    "tenant" : "rrandallaad1.onmicrosoft.com",
#    "authorityHostUrl" : "https://login.microsoftonline.com",
#    "clientId" : "624ac9bd-4c1c-4687-aec8-b56a8991cfb3",
#    "clientSecret" : "verySecret=""
# }

parameters_file = (sys.argv[1] if len(sys.argv) == 2 else
                   os.environ.get('ADAL_SAMPLE_PARAMETERS_FILE'))

if parameters_file:
    with open(parameters_file, 'r') as f:
        parameters = f.read()
    sample_parameters = json.loads(parameters)
else:
    raise ValueError('Please provide parameter file with account information.')

authority_url = (sample_parameters['authorityHostUrl'] + '/' +
                 sample_parameters['tenant'])
GRAPH_RESOURCE = '00000002-0000-0000-c000-000000000000'
RESOURCE = sample_parameters.get('resource', GRAPH_RESOURCE)

#uncomment for verbose log
#turn_on_logging()

### Main logic begins
context = adal.AuthenticationContext(
    authority_url, validate_authority=sample_parameters['tenant'] != 'adfs',
    api_version=None)

token = context.acquire_token_with_client_credentials(
    RESOURCE,
    sample_parameters['clientId'],
    sample_parameters['clientSecret'])
### Main logic ends

print('Here is the token:')
print(json.dumps(token, indent=2))
