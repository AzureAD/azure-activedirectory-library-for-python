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

import sys
import requests
import httpretty
import json

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    from unittest import mock
except ImportError:
    import mock

import adal
from adal.authentication_context import AuthenticationContext
from tests import util
from tests.util import parameters as cp

class TestRefreshToken(unittest.TestCase):
    def setUp(self):
        self.response_options = { 'refreshedRefresh' : True }
        self.response = util.create_response(self.response_options)
        self.wire_response = self.response['wireResponse']

    @httpretty.activate
    def test_happy_path_with_resource_client_secret(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], self.response['resource'], cp['clientSecret'])

        context = adal.AuthenticationContext(cp['authorityTenant'])
        def side_effect (tokenfunc):
            return self.response['decodedResponse']

        context._acquire_token = mock.MagicMock(side_effect=side_effect)

        token_response = context.acquire_token_with_refresh_token(cp['refreshToken'], cp['clientId'], cp['clientSecret'], cp['resource'])
        self.assertTrue(
            util.is_match_token_response(self.response['decodedResponse'], token_response),
            'The response did not match what was expected: ' + str(token_response)
        )

    @httpretty.activate
    def test_happy_path_with_resource_adfs(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], self.response['resource'], cp['clientSecret'])

        context = adal.AuthenticationContext(cp['authorityTenant'])
        def side_effect (tokenfunc):
            return self.response['decodedResponse']

        context._acquire_token = mock.MagicMock(side_effect=side_effect)

        token_response = context.acquire_token(cp['refreshToken'], cp['clientId'], cp['clientSecret'], cp['resource'])
        self.assertTrue(
            util.is_match_token_response(self.response['decodedResponse'], token_response),
            'The response did not match what was expected: ' + str(token_response)
        )
if __name__ == '__main__':
    unittest.main()
