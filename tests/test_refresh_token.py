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
from adal.authentication_context import AuthenticationContext, TokenCache
from tests import util
from tests.util import parameters as cp

class TestRefreshToken(unittest.TestCase):

    @httpretty.activate
    def test_happy_path_with_resource_client_secret(self):
        response_options = { 'refreshedRefresh' : True }
        response = util.create_response(response_options)
        wire_response = response['wireResponse']
        tokenRequest = util.setup_expected_refresh_token_request_response(200, wire_response, response['authority'], response['resource'], cp['clientSecret'])

        context = adal.AuthenticationContext(cp['authorityTenant'])
        def side_effect (tokenfunc):
            return response['decodedResponse']

        context._acquire_token = mock.MagicMock(side_effect=side_effect)

        token_response = context.acquire_token_with_refresh_token(cp['refreshToken'], cp['clientId'], cp['clientSecret'], cp['resource'])
        self.assertTrue(
            util.is_match_token_response(response['decodedResponse'], token_response),
            'The response did not match what was expected: ' + str(token_response)
        )

    @httpretty.activate
    def test_happy_path_with_resource_adfs(self):
        # arrange
        # set up token refresh result
        wire_response = util.create_response({ 
            'refreshedRefresh' : True,
            'mrrt': False
        })['wireResponse']
        new_resource = 'https://graph.local.azurestack.external/'
        tokenRequest = util.setup_expected_refresh_token_request_response(200, wire_response, cp['authority'], new_resource)

        # set up an existing token to be used for refreshing 
        existing_token = util.create_response({ 
            'refreshedRefresh': True,
            'mrrt': True
        })['decodedResponse']
        existing_token['_clientId'] = existing_token.get('_clientId') or cp['clientId']
        existing_token['isMRRT'] = existing_token.get('isMRRT') or True
        existing_token['_authority'] = existing_token.get('_authority') or cp['authorizeUrl']
        token_cache = TokenCache(json.dumps([existing_token]))

        # act
        user_id = existing_token['userId']
        context = adal.AuthenticationContext(cp['authorityTenant'], cache=token_cache)
        token_response = context.acquire_token(new_resource, user_id, cp['clientId'])

        # assert
        tokens = [value for key, value in token_cache.read_items()]
        self.assertEqual(2, len(tokens))
        self.assertEqual({cp['resource'], new_resource}, set([x['resource'] for x in tokens]))

if __name__ == '__main__':
    unittest.main()
