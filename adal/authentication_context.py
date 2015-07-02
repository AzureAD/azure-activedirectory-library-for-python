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
from .token_request import TokenRequest
from . import log


GLOBAL_ADAL_OPTIONS = {}

class AuthenticationContext(object):

    def __init__(self, authority, validate_authority=None):

        validate = validate_authority
        if not validate_authority:
            validate = True

        self.authority = Authority(authority, validate)
        self._oauth2client = None
        self._correlation_id = None
        self._call_context = {'options': GLOBAL_ADAL_OPTIONS}


    @property
    def options(self):
        return self._call_context['options']

    @options.setter
    def options(self, val):
        self._call_context['options'] = val

    def _acquire_token(self, callback, token_func):

        self._call_context['log_context'] = log.create_log_context(self._correlation_id)

        def _callback(err, token_response=None):
            if err:
                callback(err, token_response)
                return
            token_func(self)

        self.authority.validate(self._call_context, _callback)

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
