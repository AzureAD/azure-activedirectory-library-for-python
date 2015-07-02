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

OAUTH2_PARAMETERS = constants.OAuth2.Parameters
TOKEN_RESPONSE_FIELDS = constants.TokenResponseFields
OAUTH2_GRANT_TYPE = constants.OAuth2.GrantType
OAUTH2_SCOPE = constants.OAuth2.Scope
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
        return oauth2_client.OAuth2Client(self._call_context, self._authentication_context.authority.token_endpoint)

    def _create_self_signed_jwt(self):
        return self_signed_jwt.SelfSignedJwt(self._call_context, self._authentication_context.authority, self._client_id)

    def _oauth_get_token(self, oauth_parameters, callback):
        client = self._create_oauth2_client()
        client.get_token(oauth_parameters, callback)

    def _get_token_with_token_response(self, entry, resource, callback):
        self._log.debug("called to refresh a token from the cache")
        refresh_token = entry[TOKEN_RESPONSE_FIELDS.REFRESH_TOKEN]
        self._get_token_with_refresh_token(refresh_token, resource, None, callback)

    def _create_cache_query(self):
        query = {'clientId' : self._client_id }
        if self._user_id:
            query['userId'] = self._user_id
        else:
            self._log.debug("No user_id passed for cache query")

        return query

    def _get_token(self, callback, get_token_func):
        def _call(err, token_response=None):
            if err:
                self._log.warn("get_token_func returned with err")
                callback(err, token_response)
                return

            self._log.debug("Successfully retrieved token from authority.")
            callback(None, token_response)

        get_token_func(_call)

    def _create_oauth_parameters(self, grant_type):

        oauth_parameters = {}
        oauth_parameters[OAUTH2_PARAMETERS.GRANT_TYPE] = grant_type

        if (OAUTH2_GRANT_TYPE.AUTHORIZATION_CODE != grant_type and
            OAUTH2_GRANT_TYPE.CLIENT_CREDENTIALS != grant_type and
            OAUTH2_GRANT_TYPE.REFRESH_TOKEN != grant_type):

            oauth_parameters[OAUTH2_PARAMETERS.SCOPE] = OAUTH2_SCOPE.OPENID

        add_parameter_if_available(oauth_parameters, OAUTH2_PARAMETERS.CLIENT_ID, self._client_id)
        add_parameter_if_available(oauth_parameters, OAUTH2_PARAMETERS.RESOURCE, self._resource)
        add_parameter_if_available(oauth_parameters, OAUTH2_PARAMETERS.REDIRECT_URI, self._redirect_uri)

        return oauth_parameters

    def _get_token_username_password_managed(self, username, password, callback):
        self._log.debug('Acquiring token with username password for managed user')

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.PASSWORD)

        oauth_parameters[OAUTH2_PARAMETERS.PASSWORD] = password
        oauth_parameters[OAUTH2_PARAMETERS.USERNAME] = username

        self._oauth_get_token(oauth_parameters, callback)

    def _get_saml_grant_type(self, wstrust_response):
        token_type = wstrust_response.token_type
        if token_type == SAML.TokenTypeV1:
            return OAUTH2_GRANT_TYPE.SAML1

        elif token_type == SAML.TokenTypeV2:
            return OAUTH2_GRANT_TYPE.SAML2

        else:
            raise self._log.create_error("RSTR returned unknown token type: {0}".format(token_type))

    def _perform_wstrust_assertion_oauth_exchange(self, wstrust_response, callback):
        self._log.debug("Performing OAuth assertion grant type exchange.")

        oauth_parameters = {}
        try:
            grant_type = self._get_saml_grant_type(wstrust_response)
            assertion = b64encode(wstrust_response.token)
            oauth_parameters = self._create_oauth_parameters(grant_type)
            oauth_parameters[OAUTH2_PARAMETERS.ASSERTION] = assertion

        except Exception as exp:
            callback(exp)
            return

        self._oauth_get_token(oauth_parameters, callback)

    def _perform_wstrust_exchange(self, wstrust_endpoint, username, password, callback):
        wstrust = self._create_wstrust_request(wstrust_endpoint, "urn:federation:MicrosoftOnline")

        def _callback(rst_err, response):
            if rst_err:
                callback(rst_err, None)
                return

            if not response.token:
                rst_err = self._log.create_error("Unsuccessful RSTR.\n\terror code: {0}\n\tfaultMessage: {1}".format(response.error_code, response.fault_message))
                callback(rst_err, None)
                return
            callback(None, response)

        wstrust.acquire_token(username, password, _callback)

    def _perform_username_password_for_access_token_exchange(self, wstrust_endpoint, username, password, callback):
        def _callback(err, wstrust_response):
            if err:
                callback(err, None)
                return
            self._perform_wstrust_assertion_oauth_exchange(wstrust_response, callback)

        self._perform_wstrust_exchange(wstrust_endpoint, username, password, _callback)

    def _create_adwstrust_endpoint_error(self):
        return self._log.create_error('AAD did not return a WSTrust endpoint.  Unable to proceed.')

    def _get_token_username_password_federated(self, username, password, callback):
        self._log.debug("Acquiring token with username password for federated user")

        if not self._user_realm.federation_metadata_url:
            self._log.warn("Unable to retrieve federationMetadataUrl from AAD.  Attempting fallback to AAD supplied endpoint.")

            if not self._user_realm.federation_active_auth_url:
                callback(self._create_adwstrust_endpoint_error())
                return

            self._perform_username_password_for_access_token_exchange(self._user_realm.federation_active_auth_url, username, password, callback)
            return
        else:
            mex_endpoint = self._user_realm.federation_metadata_url
            self._log.debug("Attempting mex at: {0}".format(mex_endpoint))
            mex_instance = self._create_mex(mex_endpoint)

            def _callback(mex_err, _=None):
                if mex_err:
                    self._log.warn("MEX exchange failed.  Attempting fallback to AAD supplied endpoint.")
                    wstrust_endpoint = self._user_realm.federation_active_auth_url
                    if not wstrust_endpoint:
                        callback(self._create_adwstrust_endpoint_error())
                        return
                else:
                    wstrust_endpoint = mex_instance.username_password_url
                self._perform_username_password_for_access_token_exchange(wstrust_endpoint, username, password, callback)
                return
            mex_instance.discover(_callback)

    def _get_token_with_username_password(self, username, password, callback):

        self._log.info("Acquiring token with username password.")
        self._user_id = username

        def _callback(get_token_complete_callback):
            self._user_realm = self._create_user_realm_request(username)

            def _call(err, _=None):
                if err:
                    get_token_complete_callback(err)
                    return

                if self._user_realm.account_type == ACCOUNT_TYPE['Managed']:
                    self._get_token_username_password_managed(username, password, get_token_complete_callback)
                    return
                elif self._user_realm.account_type == ACCOUNT_TYPE['Federated']:
                    self._get_token_username_password_federated(username, password, get_token_complete_callback)
                    return
                else:
                    get_token_complete_callback(self._log.create_error("Server returned an unknown AccountType: {0}".format(self._user_realm.account_type)))
                return

            self._user_realm.discover(_call)
        self._get_token(callback, _callback)

    def _get_token_with_client_credentials(self, client_secret, callback):

        self._log.info("Getting token with client credentials.")

        def _callback(get_token_complete_callback):
            oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.CLIENT_CREDENTIALS)
            oauth_parameters[OAUTH2_PARAMETERS.CLIENT_SECRET] = client_secret
            self._oauth_get_token(oauth_parameters, get_token_complete_callback)

        self._get_token(callback, _callback)

    def _get_token_with_authorization_code(self, authorization_code, client_secret, callback):

        self._log.info("Getting token with auth code.")

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.AUTHORIZATION_CODE)
        oauth_parameters[OAUTH2_PARAMETERS.CODE] = authorization_code
        oauth_parameters[OAUTH2_PARAMETERS.CLIENT_SECRET] = client_secret

        self._oauth_get_token(oauth_parameters, callback)

    def _get_token_with_refresh_token(self, refresh_token, resource, client_secret, callback):

        self._log.info("Getting a new token from a refresh token")

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.REFRESH_TOKEN)

        if resource:
            oauth_parameters[OAUTH2_PARAMETERS.RESOURCE] = resource

        if client_secret:
            oauth_parameters[OAUTH2_PARAMETERS.CLIENT_SECRET] = client_secret

        oauth_parameters[OAUTH2_PARAMETERS.REFRESH_TOKEN] = refresh_token
        self._oauth_get_token(oauth_parameters, callback)

    def _create_jwt(self, certificate, thumbprint):

        ssj = self._create_self_signed_jwt()
        jwt = ssj.create(certificate, thumbprint)

        if not jwt:
            raise self._log.create_error("Failed to create JWT.")

        return jwt

    def get_token_with_refresh_token(self, refresh_token, client_secret, callback):
        self._get_token_with_refresh_token(refresh_token, None, client_secret, callback)

    def get_token_from_cache_with_refresh(self, user_id, callback):

        self._log.info("Getting token from cache with refresh if necessary.")

        self._user_id = user_id
        self._get_token(callback, lambda _callback: _callback(self._log.create_error("Entry not found in cache.")))

    def get_token_with_certificate(self, certificate, thumbprint, callback):

        self._log.info("Getting a token via certificate.")

        try:
            jwt = self._create_jwt(certificate, thumbprint)
        except Exception as exp:
            callback(exp, None)
            return

        oauth_parameters = self._create_oauth_parameters(OAUTH2_GRANT_TYPE.CLIENT_CREDENTIALS)
        oauth_parameters[OAUTH2_PARAMETERS.CLIENT_ASSERTION_TYPE] = OAUTH2_GRANT_TYPE.JWT_BEARER
        oauth_parameters[OAUTH2_PARAMETERS.CLIENT_ASSERTION] = jwt

        def _callback(get_token_complete_callback):
            self._oauth_get_token(oauth_parameters, get_token_complete_callback)

        self._get_token(callback, _callback)
