from . import constants
from . import log
from . import oauth2_client

OAUTH2_PARAMETERS = constants.OAuth2.Parameters

class CodeRequest(object):
    """description of class"""
    def __init__(self, call_context, authentication_context, client_id, resource):
        self._log = log.Logger("CodeRequest", call_context['log_context'])
        self._call_context = call_context
        self._authentication_context = authentication_context
        self._client_id = client_id
        self._resource = resource

    def _get_user_code_info(self, oauth_parameters, callback):
        client = self._create_oauth2_client()
        client.get_user_code_info(oauth_parameters, callback)

    def _create_oauth2_client(self):
        return oauth2_client.OAuth2Client(
            self._call_context,
            self._authentication_context.authority)

    def _create_oauth_parameters(self):
        return {
            OAUTH2_PARAMETERS.CLIENT_ID: self._client_id,
            OAUTH2_PARAMETERS.RESOURCE: self._resource
        }

    def get_user_code_info(self, language, callback):
        self._log.info('Getting user code info.')

        oauth_parameters = self._create_oauth_parameters()
        if language:
            oauth_parameters[OAUTH2_PARAMETERS.LANGUAGE] = language

        self._get_user_code_info(oauth_parameters, callback)
