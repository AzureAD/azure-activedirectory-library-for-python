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
from tests import util

from tests.util import parameters as cp

try:
    from urllib.parse import urlparse, urlencode
except ImportError:
    from urlparse import urlparse, urlencode


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

        token_response = adal._acquire_token_with_authorization_code(cp['authUrl'], cp['clientId'], cp['clientSecret'], self.authorization_code, self.redirect_uri, response['resource'])

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
