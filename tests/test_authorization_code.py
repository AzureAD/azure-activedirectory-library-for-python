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

try:
    from urllib.parse import urlparse, urlencode
except ImportError:
    from urllib import urlencode
    from urlparse import urlparse


class TestAuthorizationCode(unittest.TestCase):

    def setup_expected_auth_code_token_request_response(self, httpCode, returnDoc, authorityEndpoint=None):
        if authorityEndpoint is None:
            authorityEndpoint = '{}{}?slice=testslice&api-version=1.0'.format(cp['authUrl'], cp['tokenPath'])

        queryParameters = {}
        queryParameters['grant_type'] = 'authorization_code'
        queryParameters['code'] = self.authorization_code
        queryParameters['client_id'] = cp['clientId']
        queryParameters['client_secret'] = cp['clientSecret']
        queryParameters['resource'] = cp['resource']
        queryParameters['redirect_uri'] = self.redirect_uri

        query = urlencode(queryParameters)

        def func(body):
            return util.filter_query_strings(query, body)

        import json
        returnDocJson = json.dumps(returnDoc)
        httpretty.register_uri(httpretty.POST, authorityEndpoint, returnDocJson, status = httpCode, content_type = 'text/json')

    def setUp(self):
        self.authorization_code = '1234870909'
        self.redirect_uri = 'app_bundle:foo.bar.baz'

    @httpretty.activate
    def test_happy_path(self):
        response = util.create_response()

        self.setup_expected_auth_code_token_request_response(200, response['wireResponse'])

        context = adal.AuthenticationContext(cp['authUrl'])
        token_response = context.acquire_token_with_authorization_code(self.authorization_code, self.redirect_uri, response['resource'], cp['clientId'], cp['clientSecret'])

        self.assertTrue(util.is_match_token_response(response['decodedResponse'], token_response), 'The response did not match what was expected')

        req = httpretty.last_request()
        util.match_standard_request_headers(req)

    def test_failed_http_request(self):
        with self.assertRaises(Exception):
            adal._acquire_token_with_authorization_code(
                'https://0.1.1.1:12/my.tenant.com', cp['clientId'], cp['clientSecret'],
                self.authorization_code, self.redirect_uri, response['resource'])

    def test_bad_argument(self):
        with self.assertRaises(Exception):
            adal._acquire_token_with_authorization_code(
                'https://0.1.1.1:12/my.tenant.com', cp['clientId'], cp['clientSecret'],
                self.authorization_code, self.redirect_uri, 'BogusResource')
if __name__ == '__main__':
    unittest.main()
