#------------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. 
# All rights reserved.
# 
# This code is licensed under the MIT License.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions :
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#------------------------------------------------------------------------------

from functools import partial
from base64 import b64encode

from . import constants
from . import log
from . import mex
from . import oauth2_client
from . import self_signed_jwt
from . import user_realm
from . import wstrust_request
from .token_request_error import TokenRequestError, MexDiscoverError, DeviceCodeRequestError
from .cache_driver import CacheDriver

OAUTH2_PARAMETERS = constants.OAuth2.Parameters
TOKEN_RESPONSE_FIELDS = constants.TokenResponseFields
OAUTH2_GRANT_TYPE = constants.OAuth2.GrantType
OAUTH2_SCOPE = constants.OAuth2.Scope
#TODO: rename this for more general
OAUTH2_DEVICE_CODE_RESPONSE_PARAMETERS = constants.OAuth2.DeviceCodeResponseParameters 
SAML = constants.Saml
ACCOUNT_TYPE = constants.UserRealm.account_type

def add_parameter_if_available(parameters, key, value):
    if value:
        parameters[key] = value

class TokenRequest(object):

    def __init__(self, call_context, authentication_context, client_id, resource, redirect_uri=None):

        self._log = log.Logger("TokenRequest", call_context['log_context'])
        self._call_context = call_context

        self._authentication_context = authentication_context
        self._resource = resource
        self._client_id = client_id
        self._redirect_uri = redirect_uri

        # This should be set at the beginning of get_token
        # functions that have a user_id
        self._user_id = None
        self._user_realm = None

    def _create_user_realm_request(self, username):
        return user_realm.UserRealm(self._call_context, username, self._authentication_context.authority.url)

    def _create_mex(self, mex_endpoint):
        return mex.Mex(self._call_context, mex_endpoint)

    def _create_wstrust_request(self, wstrust_endpoint, applies_to):
        return wstrust_request.WSTrustRequest(self._call_context, wstrust_endpoint, applies_to)

    def _create_oauth2_client(self):
        return oauth2_client.OAuth2Client(self._call_context, self._authentication_context.authority)

    def _create_self_signed_jwt(self):
        return self_signed_jwt.SelfSignedJwt(self._call_context, self._authentication_context.authority, self._client_id)

    def _oauth_get_token(self, oauth_parameters):
        client = self._create_oauth2_client()
        return client.get_token(oauth_parameters)

    def _create_cache_driver(self):
        return CacheDriver(
            self._call_context,
            self._authentication_context.authority,
            self._resource,
            self._client_id,
            self._authentication_context.cache,
            self._get_token_with_token_response
        )

    def _find_token_from_cache(self):
        self._cache_driver = self._create_cache_driver()
        cache_query = self._create_cache_query()
        token = self._cache_driver.find(cache_query)
        return token

    def _add_token_into_cache(self, token):
        cache_driver = self._create_cache_driver()
        self._log.verbose('Storing retrieved token into cache')
        cache_driver.add(token)

    def _get_token_with_token_response(self, entry, resource):
        self._log.debug("called to refresh a token from the cache")
        refresh_token = entry[TOKEN_RESPONSE_FIELDS.REFRESH_TOKEN]
        self._get_token_with_refresh_token(refresh_token, resource, None)

    def _create_cache_query(self):
        query = {'clientId' : self._client_id}
        if self._user_id:
            query['userId'] = self._user_id
        else:
            self._log.debug("No user_id passed for cache query")

        return query

    #def _get_token(self, get_token_func):
    #    def _call(err, token_response=None):
    #        if err:
    #            self._log.warn("get_token_func returned with err")
    #            callback(err, token_response)
    #            return

    #        self._log.debug("Successfully retrieved token from authority.")
    #        callback(None, token_response)

    #    get_token_func(_call)

    def _create_oauth_parameters(self, grant_type):

        oauth_parameters = {}
        oauth_parameters[OAUTH2_PARAMETERS.GRANT_TYPE] = grant_type

        if (OAUTH2_GRANT_TYPE.AUTHORIZATION_CODE != grant_type and
            OAUTH2_GRANT_TYPE.CLIENT_CREDENTIALS != grant_type and
            OAUTH2_GRANT_TYPE.REFRESH_TOKEN != grant_type and
            OAUTH2_GRANT_TYPE.DEVICE_CODE != grant_type):

            oauth_parameters[OAUTH2_PARAMETERS.SCOPE] = OAUTH2_SCOPE.OPENID

        add_parameter_if_available(oauth_parameters, OAUTH2_PARAMETERS.CLIENT_ID, self._client_id)
        add_parameter_if_available(oauth_parameters, OAUTH2_PARAMETERS.RESOURCE, self._resource)
        add_parameter_if_available(oauth_parameters, OAUTH2_PARAMETERS.REDIRECT_URI, self._redirect_uri)

        return oauth_parameters

    def _get_token_username_password_managed(self, username, password):
        self._log.debug('Acquiring token with username password for managed user')

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.PASSWORD)

        oauth_parameters[OAUTH2_PARAMETERS.PASSWORD] = password
        oauth_parameters[OAUTH2_PARAMETERS.USERNAME] = username

        token = self._oauth_get_token(oauth_parameters)
        return token

    def _get_saml_grant_type(self, wstrust_response):
        token_type = wstrust_response.token_type
        if token_type == SAML.TokenTypeV1:
            return OAUTH2_GRANT_TYPE.SAML1

        elif token_type == SAML.TokenTypeV2:
            return OAUTH2_GRANT_TYPE.SAML2

        else:
            raise self._log.create_error("RSTR returned unknown token type: {0}".format(token_type))

    def _perform_wstrust_assertion_oauth_exchange(self, wstrust_response):
        self._log.debug("Performing OAuth assertion grant type exchange.")

        oauth_parameters = {}
        grant_type = self._get_saml_grant_type(wstrust_response)
        assertion = b64encode(wstrust_response.token)
        oauth_parameters = self._create_oauth_parameters(grant_type)
        oauth_parameters[OAUTH2_PARAMETERS.ASSERTION] = assertion

        token = self._oauth_get_token(oauth_parameters)
        return token

    def _perform_wstrust_exchange(self, wstrust_endpoint, username, password):
        wstrust = self._create_wstrust_request(wstrust_endpoint, "urn:federation:MicrosoftOnline")

        try:
            wstrust_response = wstrust.acquire_token(username, password)
            return wstrust_response
        except TokenRequestError as exp:
            error_msg = exp.error_msg
            if not error_msg:
                error_msg = "Unsuccessful RSTR.\n\terror code: {0}\n\tfaultMessage: {1}".format(exp.error_response.error_code, exp.error_response.fault_message)
            self._log.create_error(error_msg)
            raise exp

    def _perform_username_password_for_access_token_exchange(self, wstrust_endpoint, username, password):
        wstrust_response = self._perform_wstrust_exchange(wstrust_endpoint, username, password)
        token = self._perform_wstrust_assertion_oauth_exchange(wstrust_response)
        return token

    def _get_token_username_password_federated(self, username, password):
        self._log.debug("Acquiring token with username password for federated user")

        if not self._user_realm.federation_metadata_url:
            self._log.warn("Unable to retrieve federationMetadataUrl from AAD.  Attempting fallback to AAD supplied endpoint.")

            if not self._user_realm.federation_active_auth_url:
                raise TokenRequestError('AAD did not return a WSTrust endpoint.  Unable to proceed.')

            token = self._perform_username_password_for_access_token_exchange(self._user_realm.federation_active_auth_url, username, password)
            return token
        else:
            mex_endpoint = self._user_realm.federation_metadata_url
            self._log.debug("Attempting mex at: {0}".format(mex_endpoint))
            mex_instance = self._create_mex(mex_endpoint)
            wstrust_endpoint = None
             
            try:
                mex_instance.discover()
                wstrust_endpoint = mex_instance.username_password_url
            except:
                self._log.warn("MEX exchange failed.  Attempting fallback to AAD supplied endpoint.")
                wstrust_endpoint = self._user_realm.federation_active_auth_url
                if not wstrust_endpoint:
                    raise TokenRequestError('AAD did not return a WSTrust endpoint.  Unable to proceed.')

            token = self._perform_username_password_for_access_token_exchange(wstrust_endpoint, username, password)
            return token

    def get_token_with_username_password(self, username, password):
        self._log.info("Acquiring token with username password.")
        self._user_id = username
        try:
            token = self._find_token_from_cache()
            if token:
                return token
        except Exception as exp:
            #TODO: ensure we dump out the stacks
            self._log.warn('Attempt to look for token in cache resulted in Error: {}'.format(exp))
 
        self._user_realm = self._create_user_realm_request(username)
        self._user_realm.discover()

        try:
            if self._user_realm.account_type == ACCOUNT_TYPE['Managed']:
                token = self._get_token_username_password_managed(username, password)
            elif self._user_realm.account_type == ACCOUNT_TYPE['Federated']:
                token = self._get_token_username_password_federated(username, password)
            else:
                raise TokenRequestError(self._log.create_error("Server returned an unknown AccountType: {0}".format(self._user_realm.account_type)))
            self._log.debug("Successfully retrieved token from authority.")
        except Exception as exp:
            self._log.warn("get_token_func returned with err")
            raise exp
        
        self._cache_driver.add(token)
        return token

    # this is public method
    def get_token_with_client_credentials(self, client_secret):
        self._log.info("Getting token with client credentials.")
        try:
            token = self._find_token_from_cache()
            return token
        except Exception as exp:
            #TODO: ensure we dump out the stacks
            self._log.warn('Attempt to look for token in cache resulted in Error: {}'.format(exp))

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.CLIENT_CREDENTIALS)
        oauth_parameters[OAUTH2_PARAMETERS.CLIENT_SECRET] = client_secret

        token = self._oauth_get_token(oauth_parameters)
        self._cache_driver.add(token)
        return token

    def get_token_with_authorization_code(self, authorization_code, client_secret):

        self._log.info("Getting token with auth code.")

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.AUTHORIZATION_CODE)
        oauth_parameters[OAUTH2_PARAMETERS.CODE] = authorization_code
        oauth_parameters[OAUTH2_PARAMETERS.CLIENT_SECRET] = client_secret

        token = self._oauth_get_token(oauth_parameters)
        self._cache_driver.add(token)
        return token

    def _get_token_with_refresh_token(self, refresh_token, resource, client_secret):

        self._log.info("Getting a new token from a refresh token")

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.REFRESH_TOKEN)
        if resource:
            oauth_parameters[OAUTH2_PARAMETERS.RESOURCE] = resource

        if client_secret:
            oauth_parameters[OAUTH2_PARAMETERS.CLIENT_SECRET] = client_secret

        oauth_parameters[OAUTH2_PARAMETERS.REFRESH_TOKEN] = refresh_token
        token = self._oauth_get_token(oauth_parameters)
        return token

    def get_token_with_refresh_token(self, refresh_token, client_secret):
        token = self._get_token_with_refresh_token(refresh_token, None, client_secret)
        return token

    def get_token_from_cache_with_refresh(self, user_id):
        self._log.info("Getting token from cache with refresh if necessary.")
        self._user_id = user_id
        token = self._find_token_from_cache()
        return token

    def _create_jwt(self, certificate, thumbprint):

        ssj = self._create_self_signed_jwt()
        jwt = ssj.create(certificate, thumbprint)

        if not jwt:
            raise self._log.create_error("Failed to create JWT.")

        return jwt    
    
    def get_token_with_certificate(self, certificate, thumbprint):

        self._log.info("Getting a token via certificate.")

        jwt = self._create_jwt(certificate, thumbprint)

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.CLIENT_CREDENTIALS)
        oauth_parameters[OAUTH2_PARAMETERS.CLIENT_ASSERTION_TYPE] = OAUTH2_GRANT_TYPE.JWT_BEARER
        oauth_parameters[OAUTH2_PARAMETERS.CLIENT_ASSERTION] = jwt

        token = None
        try:
            token = self._find_token_from_cache()
        except: #catch specific exception
            token = self._oauth_get_token(oauth_parameters)

        return token

    def get_token_with_device_code(self, user_code_info):
        self._log.info("Getting a token via device code")

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.DEVICE_CODE)
        oauth_parameters[OAUTH2_PARAMETERS.CODE] = user_code_info[OAUTH2_DEVICE_CODE_RESPONSE_PARAMETERS.DEVICE_CODE]

        interval = user_code_info[OAUTH2_DEVICE_CODE_RESPONSE_PARAMETERS.INTERVAL]
        expires_in = user_code_info[OAUTH2_DEVICE_CODE_RESPONSE_PARAMETERS.EXPIRES_IN]

        if interval <= 0:
            raise DeviceCodeRequestError('invalid refresh interval')

        client = self._create_oauth2_client()
        self._polling_client = client

        token = client.get_token_with_polling(oauth_parameters, interval, expires_in)
        self._add_token_into_cache(token)

        return token

    def _cancel_token_request_with_device_code(self):
        self._polling_client.cancel_polling_request()
