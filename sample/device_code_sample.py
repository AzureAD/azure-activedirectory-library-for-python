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

# You can provide account information by using a JSON file
# with the same parameters as the sampleParameters variable below.  Either
# through a command line argument, 'python sample.py parameters.json', or
# specifying in an environment variable of ADAL_SAMPLE_PARAMETERS_FILE.
#
# The information inside such file can be obtained via app registration.
# See https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki/Register-your-application-with-Azure-Active-Directory
#
# {
#    "resource": "your_resource",
#    "tenant" : "rrandallaad1.onmicrosoft.com",
#    "authorityHostUrl" : "https://login.microsoftonline.com",
#    "clientId" : "624ac9bd-4c1c-4687-aec8-b56a8991cfb3",
#    "anothertenant" : "bar.onmicrosoft.com"
# }

parameters_file = (sys.argv[1] if len(sys.argv) == 2 else
                   os.environ.get('ADAL_SAMPLE_PARAMETERS_FILE'))

if parameters_file:
    with open(parameters_file, 'r') as f:
        parameters = f.read()
    sample_parameters = json.loads(parameters)
else:
    raise ValueError('Please provide parameter file with account information.')


authority_host_url = sample_parameters['authorityHostUrl']
authority_url = authority_host_url + '/' + sample_parameters['tenant']
clientid = sample_parameters['clientId']
GRAPH_RESOURCE = '00000002-0000-0000-c000-000000000000'
RESOURCE = sample_parameters.get('resource', GRAPH_RESOURCE)

#uncomment for verbose logging
#turn_on_logging()

### Main logic begins
context = adal.AuthenticationContext(authority_url, api_version=None)
code = context.acquire_user_code(RESOURCE, clientid)
print(code['message'])
token = context.acquire_token_with_device_code(RESOURCE, code, clientid)
### Main logic ends

print('Here is the token from "{}":'.format(authority_url))
print(json.dumps(token, indent=2))

#try cross tenant token refreshing
another_tenant = sample_parameters.get('anothertenant')
if another_tenant:
    authority_url = authority_host_url + '/' + another_tenant
    #reuse existing cache which has the tokens acquired early on
    existing_cache = context.cache
    context = adal.AuthenticationContext(authority_url, cache=existing_cache)
    token = context.acquire_token(RESOURCE, token['userId'], clientid)
    print('Here is the token from "{}":'.format(authority_url))
    print(json.dumps(token, indent=2))

