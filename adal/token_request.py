#-------------------------------------------------------------------------
#
# Copyright Microsoft Open Technologies, Inc.
#
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http: *www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
# PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
# See the Apache License, Version 2.0 for the specific language
# governing permissions and limitations under the License.
#
#--------------------------------------------------------------------------

from . import constants
from . import log
from . import mex
from . import oauth2_client
from . import self_signed_jwt
from . import user_realm
from . import wstrust_request

from functools import partial
from base64 import b64encode

OAuth2Parameters = constants.OAuth2.Parameters
TokenResponseFields = constants.TokenResponseFields
OAuth2GrantType = constants.OAuth2.GrantType
OAuth2Scope = constants.OAuth2.Scope
Saml = constants.Saml
AccountType = constants.UserRealm.account_type

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
        return user_realm.UserRealm(self._call_context, username, self._authentication_context.authority)

    def _create_mex(self, mex_endpoint):
        return mex.Mex(self._call_context, mex_endpoint)

    def _create_wstrust_request(self, wstrust_endpoint, applies_to):
        return wstrust_request.WSTrustRequest(self._call_context, wstrust_endpoint, applies_to)

    def _create_oauth2_client(self):
        return oauth2_client.OAuth2Client(self._call_context, self._authentication_context._authority.token_endpoint)

    def _create_self_signed_jwt(self):
        return self_signed_jwt.SelfSignedJwt(self._call_context, self._authentication_context._authority, self._client_id)

    def _oauth_get_token(self, oauth_parameters, callback):
        client = self._create_oauth2_client()
        client.get_token(oauth_parameters, callback)

    def _get_token_with_token_response(self, entry, resource, callback):
        self._log.debug("called to refresh a token from the cache")
        refresh_token = entry[TokenResponseFields.REFRESH_TOKEN]
        self._get_token_with_refresh_token(refresh_token, resource, None, callback)

    def _create_cache_query(self):
        query = {'clientId':self._client_id }
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
        oauth_parameters[OAuth2Parameters.GRANT_TYPE] = grant_type

        if (OAuth2GrantType.AUTHORIZATION_CODE != grant_type and
            OAuth2GrantType.CLIENT_CREDENTIALS != grant_type and
            OAuth2GrantType.REFRESH_TOKEN != grant_type):

            oauth_parameters[OAuth2Parameters.SCOPE] = OAuth2Scope.OPENID

        add_parameter_if_available(oauth_parameters, OAuth2Parameters.CLIENT_ID, self._client_id)
        add_parameter_if_available(oauth_parameters, OAuth2Parameters.RESOURCE, self._resource)
        add_parameter_if_available(oauth_parameters, OAuth2Parameters.REDIRECT_URI, self._redirect_uri)

        return oauth_parameters

    def _get_token_username_password_managed(self, username, password, callback):
        self._log.debug('Acquiring token with username password for managed user')

        oauth_parameters = self._create_oauth_parameters(OAuth2GrantType.PASSWORD)

        oauth_parameters[OAuth2Parameters.PASSWORD] = password
        oauth_parameters[OAuth2Parameters.USERNAME] = username

        self._oauth_get_token(oauth_parameters, callback)

    def _get_saml_grant_type(self, wstrust_response):
        token_type = wstrust_response.token_type
        if token_type == Saml.TokenTypeV1:
            return OAuth2GrantType.SAML1

        elif token_type == Saml.TokenTypeV2:
            return OAuth2GrantType.SAML2

        else:
            raise self._log.create_error("RSTR returned unknown token type: {0}".format(token_type))

    def _perform_wstrust_assertion_oauth_exchange(self, wstrust_response, callback):
        self._log.debug("Performing OAuth assertion grant type exchange.")

        oauth_parameters = {}
        try:
            grant_type = self._get_saml_grant_type(wstrust_response)
            assertion = b64encode(wstrust_response.token)
            oauth_parameters = self._create_oauth_parameters(grant_type)
            oauth_parameters[OAuth2Parameters.ASSERTION] = assertion

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
            mex = self._create_mex(mex_endpoint)

            def _callback(mex_err, _=None):
                if mex_err:
                    self._log.warn("MEX exchange failed.  Attempting fallback to AAD supplied endpoint.")
                    wstrust_endpoint = self._user_realm.federation_active_auth_url
                    if not wstrust_endpoint:
                        callback(self._create_adwstrust_endpoint_error())
                        return
                else:
                    wstrust_endpoint = mex.username_password_url
                self._perform_username_password_for_access_token_exchange(wstrust_endpoint, username, password, callback)
                return
            mex.discover(_callback)

    def _get_token_with_username_password(self, username, password, callback):

        self._log.info("Acquiring token with username password.")
        self._user_id = username

        def _callback(get_token_complete_callback):
            self._user_realm = self._create_user_realm_request(username)

            def _call(err, response=None):
                if err:
                    get_token_complete_callback(err)
                    return

                if self._user_realm.account_type == AccountType['Managed']:
                    self._get_token_username_password_managed(username, password, get_token_complete_callback)
                    return
                elif self._user_realm.account_type == AccountType['Federated']:
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
            oauth_parameters = self._create_oauth_parameters(OAuth2GrantType.CLIENT_CREDENTIALS)
            oauth_parameters[OAuth2Parameters.CLIENT_SECRET] = client_secret
            self._oauth_get_token(oauth_parameters, get_token_complete_callback)

        self._get_token(callback, _callback)

    def _get_token_with_authorization_code(self, authorization_code, client_secret, callback):

        self._log.info("Getting token with auth code.")

        oauth_parameters = self._create_oauth_parameters(OAuth2GrantType.AUTHORIZATION_CODE)
        oauth_parameters[OAuth2Parameters.CODE] = authorization_code
        oauth_parameters[OAuth2Parameters.CLIENT_SECRET] = client_secret

        self._oauth_get_token(oauth_parameters, callback)

    def _get_token_with_refresh_token(self, refresh_token, resource, client_secret, callback):

        self._log.info("Getting a new token from a refresh token")

        oauth_parameters = self._create_oauth_parameters(OAuth2GrantType.REFRESH_TOKEN)

        if resource:
            oauth_parameters[OAuth2Parameters.RESOURCE] = resource

        if client_secret:
            oauth_parameters[OAuth2Parameters.CLIENT_SECRET] = client_secret

        oauth_parameters[OAuth2Parameters.REFRESH_TOKEN] = refresh_token
        self._oauth_get_token(oauth_parameters, callback)

    def _create_jwt(self, authority_url, certificate, thumbprint):

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

        authority_url = self._authentication_context._authority

        try:
            jwt = self._create_jwt(authority_url, certificate, thumbprint)
        except Exception as exp:
            callback(exp, None)
            return

        oauth_parameters = self._create_oauth_parameters(OAuth2GrantType.CLIENT_CREDENTIALS)
        oauth_parameters[OAuth2Parameters.CLIENT_ASSERTION_TYPE] = OAuth2GrantType.JWT_BEARER
        oauth_parameters[OAuth2Parameters.CLIENT_ASSERTION] = jwt

        def _callback(get_token_complete_callback):
            self._oauth_get_token(oauth_parameters, get_token_complete_callback)

        self._get_token(callback, _callback)
