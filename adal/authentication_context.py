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

from .memory_cache import MemoryCache
from .authority import Authority
from . import argument
from .token_request import TokenRequest
from . import util
from . import log


global_ADAL_options = {}
global_cache = MemoryCache()

def get_ADAL_options():
    return global_ADAL_options

def set_ADAL_options(options):
    global_ADAL_options = options

class AuthenticationContext(object):

    def __init__(self, authority, validate_authority = None, cache = None):

        validate = validate_authority
        if not validate_authority:
            validate = True

        self._authority = Authority(authority, validate)
        self._oauth2client = None
        self._correlation_id = None
        self._call_context = {'options': global_ADAL_options}
        self._cache = cache if cache else global_cache

    @property
    def authority(self):
        return self._authority.url

    @property
    def cache(self):
        return self._cache

    @property
    def correlation_id(self):
        return self._correlation_id

    @correlation_id.setter
    def correlation_id(self, val):
        self._correlation_id = val

    @property
    def options(self):
        return self._call_context['options']

    @options.setter
    def options(self, val):
        self._call_context['options'] = val

    def _acquire_token(self, callback, token_func):

        self._call_context['log_context'] = log.create_log_context(self._correlation_id)

        def _callback(err):
            if err:
                callback(err)
                return
            token_func(self)

        self._authority.validate(self._call_context, _callback)

    def acquire_token(self, resource, user_id, client_id, callback):

        argument.validate_callback_type(callback)
        try:
            argument.validate_string_param(resource, 'resource')
            argument.validate_string_param(client_id, 'client_id')
        except Exception as exp:
            callback(exp)
            return

        def token_func(self):
            self.token_request = TokenRequest(self._call_context, self, client_id, resource)
            self.token_request.get_token_from_cache_with_refresh(user_id, callback)

        self._acquire_token(callback, token_func)

    def acquire_token_with_username_password(self, resource, username, password, client_id, callback):

        argument.validate_callback_type(callback)
        try:
            argument.validate_string_param(resource, 'resource')
            argument.validate_string_param(username, 'username')
            argument.validate_string_param(password, 'password')
            argument.validate_string_param(client_id, 'client_id')
        except Exception as exp:
            callback(exp)
            return

        def token_func(self):
            self.token_request = TokenRequest(self._call_context, self, client_id, resource)
            self.token_request._get_token_with_username_password(username, password, callback)

        self._acquire_token(callback, token_func)

    def acquire_token_with_client_credentials(self, resource, client_id, client_secret, callback):

        argument.validate_callback_type(callback)
        try:
            argument.validate_string_param(resource, 'resource')
            argument.validate_string_param(client_id, 'client_id')
            argument.validate_string_param(client_secret, 'client_secret')
        except Exception as exp:
            callback(exp)
            return

        def token_func(self, extra=None):
            self.token_request = TokenRequest(self._call_context, self, client_id, resource)
            self.token_request._get_token_with_client_credentials(client_secret, callback)

        self._acquire_token(callback, token_func)

    def acquire_token_with_authorization_code(self, authorization_code, redirect_uri, resource, client_id, client_secret, callback):

        argument.validate_callback_type(callback)
        try:
            argument.validate_string_param(resource, 'resource')
            argument.validate_string_param(authorization_code, 'authorization_code')
            argument.validate_string_param(redirect_uri, 'redirect_uri')
            argument.validate_string_param(client_id, 'client_id')
            argument.validate_string_param(client_secret, 'client_secret')
        except Exception as exp:
            callback(exp)
            return

        def token_func(self):
            self.token_request = TokenRequest(self._call_context, self, client_id, resource, redirect_uri)
            self.token_request._get_token_with_authorization_code(authorization_code, client_secret, callback)

        self._acquire_token(callback, token_func)

    def acquire_token_with_refresh_token(self, refresh_token, client_id, *args):
        # Fix up the arguments.  Older clients may pass fewer arguments as the clientSecret parameter did not always exist.
        # The code needs to make adjustments for those clients.

        client_secret_present = (len(args) == 3)
        client_secret = args[0] if client_secret_present else None
        resource = args[1] if client_secret_present else args[0]
        callback = args[2] if client_secret_present else args[1]

        argument.validate_callback_type(callback)
        try:
            argument.validate_string_param(refresh_token, 'refresh_token')
            argument.validate_string_param(client_id, 'client_id')

        except Exception as exp:
            callback(exp)
            return

        def token_func(self):
            self.token_request = TokenRequest(self._call_context, self, client_id, resource)
            self.token_request.get_token_with_refresh_token(refresh_token, client_secret, callback)

        self._acquire_token(callback, token_func)

    def acquire_token_with_client_certificate(self, resource, client_id, certificate, thumbprint, callback):

        argument.validate_callback_type(callback)
        try:
            argument.validate_string_param(resource, 'resource')
            argument.validate_string_param(certificate, 'certificate')
            argument.validate_string_param(thumbprint, 'thumbprint')
        except Exception as exp:
            callback(exp)
            return

        def token_func(self):
            self.token_request = TokenRequest(self._call_context, self, client_id, resource)
            self.token_request.get_token_with_certificate(certificate, thumbprint, callback)

        self._acquire_token(callback, token_func)