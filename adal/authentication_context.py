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

from .authority import Authority

from . import argument
from .code_request import CodeRequest
from .token_request import TokenRequest
from .token_cache import TokenCache
from . import log
from .constants import OAuth2DeviceCodeResponseParameters


GLOBAL_ADAL_OPTIONS = {}

class AuthenticationContext(object):

    def __init__(self, authority, validate_authority=None, cache=None):

        validate = validate_authority
        if not validate_authority:
            validate = True

        self.authority = Authority(authority, validate)
        self._oauth2client = None
        self._correlation_id = None
        self._call_context = {'options': GLOBAL_ADAL_OPTIONS}
        self._token_requests_with_user_code = {}
        self.cache = cache or TokenCache()

    @property
    def options(self):
        return self._call_context['options']

    @options.setter
    def options(self, val):
        self._call_context['options'] = val

    def _acquire_token(self, token_func):
        self._call_context['log_context'] = log.create_log_context(self._correlation_id)
        self.authority.validate(self._call_context)
        token = token_func(self)
        return token

    def acquire_token(self, resource, user_id, client_id):
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(client_id, 'client_id')

        def token_func(self): #make sure this 'self' works
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            token = token_request.get_token_from_cache_with_refresh(user_id)
            return token

        token = self._acquire_token(token_func)
        return token

    def acquire_token_with_username_password(self, resource, username, password, client_id):
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(username, 'username')
        argument.validate_string_param(password, 'password')
        argument.validate_string_param(client_id, 'client_id')

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            token = token_request.get_token_with_username_password(username, password)
            return token

        token = self._acquire_token(token_func)
        return token

    def acquire_token_with_client_credentials(self, resource, client_id, client_secret):
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(client_id, 'client_id')
        argument.validate_string_param(client_secret, 'client_secret')

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            token = token_request.get_token_with_client_credentials(client_secret)
            return token

        token = self._acquire_token(token_func)
        return token

    def acquire_token_with_authorization_code(self, authorization_code, redirect_uri, resource, client_id, client_secret):

        argument.validate_string_param(authorization_code, 'authorization_code')
        argument.validate_string_param(redirect_uri, 'redirect_uri')
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(client_id, 'client_id')
        argument.validate_string_param(client_secret, 'client_secret')
 
        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource, redirect_uri)
            token = token_request.get_token_with_authorization_code(authorization_code, client_secret)
            return token

        token = self._acquire_token(token_func)
        return token

    def acquire_token_with_refresh_token(
        self,
        refresh_token,
        client_id,
        client_secret, 
        resource
    ):
        argument.validate_string_param(refresh_token, 'refresh_token')
        argument.validate_string_param(client_id, 'client_id')
        argument.validate_string_param(resource, 'resource')
        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            token = token_request.get_token_with_refresh_token(refresh_token, client_secret)
            return token

        token = self._acquire_token(token_func)
        return token

    def acquire_token_with_client_certificate(
        self,
        resource,
        client_id,
        certificate,
        thumbprint
    ):
        argument.validate_string_param(resource, 'resource')
        argument.validate_string_param(client_id, 'client_id')
        argument.validate_string_param(certificate, 'certificate')
        argument.validate_string_param(thumbprint, 'thumbprint')

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            token = token_request.get_token_with_certificate(certificate, thumbprint)
            return token

        token = self._acquire_token(token_func)
        return token

    def acquire_user_code(self, resource, client_id, language=None):
        self._call_context['log_context'] = log.create_log_context(self._correlation_id)
        self.authority.validate(self._call_context)
        code_request = CodeRequest(self._call_context, self, client_id, resource)
        code = code_request.get_user_code_info(language)
        return code

    def acquire_token_with_device_code(self, resource, user_code_info, client_id):
        self._call_context['log_context'] = log.create_log_context(self._correlation_id)

        def token_func(self):
            token_request = TokenRequest(self._call_context, self, client_id, resource)
            self._token_requests_with_user_code[user_code_info[OAuth2DeviceCodeResponseParameters.DEVICE_CODE]] = token_request 
            token = token_request.get_token_with_device_code(user_code_info)
            return token

        token = self._acquire_token(token_func)
        return token

    def cancel_request_to_get_token_with_device_code(self, user_code_info):
        argument.validate_user_code_info(user_code_info)
        
        key = user_code_info[OAuth2DeviceCodeResponseParameters.DEVICE_CODE]
        request = self._token_requests_with_user_code.get(key)
        if  not request:
            raise ValueError('No acquire_token_with_device_code existed to be cancelled')

        request._cancel_token_request_with_device_code()
        self._token_requests_with_user_code.pop(key, None)
