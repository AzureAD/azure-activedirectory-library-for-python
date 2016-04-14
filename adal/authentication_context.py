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

import threading

from .authority import Authority
from . import argument
from .code_request import CodeRequest
from .token_request import TokenRequest
from .token_cache import TokenCache
from . import log
from .constants import OAuth2DeviceCodeResponseParameters

GLOBAL_ADAL_OPTIONS = {}

class AuthenticationContext(object):
    '''
    Retrieves authentication tokens from Azure Active Directory.
    For usages, check out the "sample" folder at:
        https://github.com/AzureAD/azure-activedirectory-library-for-python
    '''
    def __init__(self, authority, validate_authority=None, cache=None):
        '''
        Creates a new AuthenticationContext object. By default the authority
        will be checked against a list of known Azure Active Directory
        authorities. If the authority is not recognized as one of these well
        known authorities then token acquisition will fail. This behavior can
        be turned off via the validate_authority parameter below.

        :param str authority: A URL that identifies a token authority.
        :param bool validate_authority: (optional) Turns authority validation 
            on or off. This parameter default to true.
        :param TokenCache cache: (optional) Sets the token cache used by this 
            AuthenticationContext instance. If this parameter is not set, then
            a default is used. Cache instances is only used by that instance of
            the AuthenticationContext and are not shared unless it has been
            manually passed during the construction of other
            AuthenticationContexts.
        '''
        validate = validate_authority
        if not validate_authority:
            validate = True

        self.authority = Authority(authority, validate)
        self._oauth2client = None
        self.correlation_id = None
        self._call_context = {'options': GLOBAL_ADAL_OPTIONS}
        self._token_requests_with_user_code = {}
        self.cache = cache or TokenCache()
        self._lock = threading.RLock()

    @property
    def options(self):
        return self._call_context['options']

    @options.setter
    def options(self, val):
        self._call_context['options'] = val

    def _acquire_token(self, token_func):
        self._call_context['log_context'] = log.create_log_context(self.correlation_id)
        self.authority.validate(self._call_context)
        return token_func(self)

    def acquire_token(self, resource, user_id, client_id):
        '''
        Gets a token for a given resource via cached tokens.

        :param str resource: A URI that identifies the resource for which the
            token is valid.
        :param str user_id: The username of the user on behalf this application
            is authenticating.
        :param str client_id: The OAuth client id of the calling application.
        :returns: dic with several keys, include "accessToken" and
            "refreshToken".
        '''
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(client_id, 'client_id')

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            return token_request.get_token_from_cache_with_refresh(user_id)

        return self._acquire_token(token_func)       

    def acquire_token_with_username_password(self, resource, username, password, client_id):
        '''
        Gets a token for a given resource via user credentails.
        
        :param str resource: A URI that identifies the resource for which the 
            token is valid.
        :param str username: The username of the user on behalf this
            application is authenticating.
        :param str password: The password of the user named in the username
            parameter.
        :param str client_id: The OAuth client id of the calling application.
        :returns: dict with several keys, include "accessToken" and
            "refreshToken".
        '''
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(username, 'username')
        argument.validate_string_param(password, 'password')
        argument.validate_string_param(client_id, 'client_id')

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            return token_request.get_token_with_username_password(username, password)

        return self._acquire_token(token_func)

    def acquire_token_with_client_credentials(self, resource, client_id, client_secret):
        '''
        Gets a token for a given resource via client credentials.

        :param str resource: A URI that identifies the resource for which the 
            token is valid.
        :param str client_id: The OAuth client id of the calling application.
        :param str client_secret: The OAuth client secret of the calling application.
        :returns: dict with several keys, include "accessToken".
        '''
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(client_id, 'client_id')
        argument.validate_string_param(client_secret, 'client_secret')

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            return token_request.get_token_with_client_credentials(client_secret)

        return self._acquire_token(token_func)

    def acquire_token_with_authorization_code(
            self, 
            authorization_code, 
            redirect_uri, 
            resource, 
            client_id, 
            client_secret):
        '''
        Gets a token for a given resource via auhtorization code for a server
        app.
        
        :param str authorization_code: An authorization code returned from a
            client.
        :param str redirect_uri: the redirect uri that was used in the
            authorize call.
        :param str resource: A URI that identifies the resource for which the
            token is valid.
        :param str client_id: The OAuth client id of the calling application.
        :param str client_secret: The OAuth client secret of the calling
            application.
        :returns: dict with several keys, include "accessToken" and
            "refreshToken".
        '''
        argument.validate_string_param(authorization_code, 'authorization_code')
        argument.validate_string_param(redirect_uri, 'redirect_uri')
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(client_id, 'client_id')
        argument.validate_string_param(client_secret, 'client_secret')
 
        def token_func(self):
            token_request = TokenRequest(
                self._call_context, 
                self, 
                client_id, 
                resource, 
                redirect_uri)
            return token_request.get_token_with_authorization_code(
                authorization_code, 
                client_secret)

        return self._acquire_token(token_func)

    def acquire_token_with_refresh_token(self, refresh_token, client_id, resource, client_secret=None):
        '''
        Gets a token for a given resource via refresh tokens
        
        :param str refresh_token: A refresh token returned in a tokne response
            from a previous invocation of acquireToken.
        :param str client_id: The OAuth client id of the calling application.
        :param str resource: A URI that identifies the resource for which the
            token is valid.
        :param str client_secret: (optional)The OAuth client secret of the
            calling application.                 
        :returns: dict with several keys, include "accessToken" and
            "refreshToken".
        '''
        argument.validate_string_param(refresh_token, 'refresh_token')
        argument.validate_string_param(client_id, 'client_id')
        argument.validate_string_param(resource, 'resource')
        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            return token_request.get_token_with_refresh_token(refresh_token, client_secret)

        return self._acquire_token(token_func)

    def acquire_token_with_client_certificate(self, resource, client_id, certificate, thumbprint):
        '''
        Gets a token for a given resource via certificate credentials

        :param str resource: A URI that identifies the resource for which the
            token is valid.
        :param str client_id: The OAuth client id of the calling application.
        :param str certificate: A PEM encoded certificate private key.
        :param str thumbprint:  hex encoded thumbprint of the certificate.
        :returns: dict with several keys, include "accessToken".
        '''
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(client_id, 'client_id')
        argument.validate_string_param(certificate, 'certificate')
        argument.validate_string_param(thumbprint, 'thumbprint')

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            return token_request.get_token_with_certificate(certificate, thumbprint)

        return self._acquire_token(token_func)

    def acquire_user_code(self, resource, client_id, language=None):
        '''
        Gets the user code info which contains user_code, device_code for
        authenticating user on device.
        
        :param str resource: A URI that identifies the resource for which the 
            device_code and user_code is valid for.
        :param str client_id: The OAuth client id of the calling application.
        :param str language: The language code specifying how the message
            should be localized to.
        :returns: dict contains code and uri for users to login through browser.
        '''
        self._call_context['log_context'] = log.create_log_context(self.correlation_id)
        self.authority.validate(self._call_context)
        code_request = CodeRequest(self._call_context, self, client_id, resource)
        return code_request.get_user_code_info(language)

    def acquire_token_with_device_code(self, resource, user_code_info, client_id):
        '''
        Gets a new access token using via a device code. 
        
        :param str resource: A URI that identifies the resource for which the
            token is valid.
        :param dict user_code_info: The code info from the invocation of
            "acquire_user_code"
        :param str client_id: The OAuth client id of the calling application.
        :returns: dict with several keys, include "accessToken" and
            "refreshToken".
        '''
        self._call_context['log_context'] = log.create_log_context(self.correlation_id)

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)

            key = user_code_info[OAuth2DeviceCodeResponseParameters.DEVICE_CODE]
            with self._lock:
                self._token_requests_with_user_code[key] = token_request

            token = token_request.get_token_with_device_code(user_code_info)
            
            with self._lock:
                self._token_requests_with_user_code.pop(key, None)
            
            return token

        return self._acquire_token(token_func)

    def cancel_request_to_get_token_with_device_code(self, user_code_info):
        '''
        Cancels the polling request to get token with device code. 

        :param dict user_code_info: The code info from the invocation of
            "acquire_user_code"
        :returns: None
        '''
        argument.validate_user_code_info(user_code_info)
        
        key = user_code_info[OAuth2DeviceCodeResponseParameters.DEVICE_CODE]
        with self._lock:
            request = self._token_requests_with_user_code.get(key)

            if not request:
                raise ValueError('No acquire_token_with_device_code existed to be cancelled')

            request.cancel_token_request_with_device_code()
            self._token_requests_with_user_code.pop(key, None)
