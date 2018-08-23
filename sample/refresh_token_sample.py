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

# You can override the account information by using a JSON file. Either
# through a command line argument, 'python sample.py parameters.json', or
# specifying in an environment variable of ADAL_SAMPLE_PARAMETERS_FILE.
#
# The information inside such file can be obtained via app registration.
# See https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki/Register-your-application-with-Azure-Active-Directory
#
# {
#   "resource": "your_resource",
#   "tenant" : "rrandallaad1.onmicrosoft.com",
#   "authorityHostUrl" : "https://login.microsoftonline.com",
#   "clientId" : "624ac9bd-4c1c-4687-aec8-b56a8991cfb3",
#   "username" : "user1",
#   "password" : "verySecurePassword"
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
    )


def action1():
    print("\nbasic_action – This indicates a simple action is required by the end user, like MFA. ")


def action2():
    print(
        "\nThis indicates additional action is required that is in the user control, but is outside of the sign in session. For example, enroll in MDM or register install an app that uses Intune app protection.")


def action3():
    print(
        "message_only – User will be shown an informational message with no immediate remediation steps. For example, access was blocked due to location or the device is not domain joined.")


try:
    token = context.acquire_token_with_username_password(
        RESOURCE,
        sample_parameters['username'],
        sample_parameters['password'],
        sample_parameters['clientId'])
except Exception as e:
    print("\nAction to be taken  : " + e.sub_error)

    options = {"basic_action": action1,
               "additional_action": action2,
               "message_only": action3}
    options[e.sub_error]()

    print("\nLink to information about this action: " + e.remote_url)
