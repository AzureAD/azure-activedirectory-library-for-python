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
import six

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    from unittest import mock
except ImportError:
    import mock

import adal
from adal.authority import Authority
from adal import log
from adal.authentication_context import AuthenticationContext
from tests import util
from tests.util import parameters as cp

try:
    from urllib.parse import urlparse

except ImportError:
    from urlparse import urlparse


class TestAuthority(unittest.TestCase):

    # use this as authority to force dynamic as opposed to static instance
    # discovery.
    nonHardCodedAuthority = 'https://login.doesntexist.com/' + cp['tenant']
    nonHardCodedAuthorizeEndpoint = nonHardCodedAuthority + '/oauth2/authorize'


    def setUp(self):
        util.reset_logging()
        util.clear_static_cache()
        return super(TestAuthority, self).setUp()

    def tearDown(self):
        util.reset_logging()
        util.clear_static_cache()
        return super(TestAuthority, self).tearDown()

    def setupExpectedInstanceDiscoveryRequestRetries(self, requestParametersList, authority):
        pass

    @httpretty.activate
    def test_success_dynamic_instance_discovery(self):
        instanceDiscoveryRequest = util.setup_expected_instance_discovery_request(
            200,
            cp['authorityHosts']['global'],
            {'tenant_discovery_endpoint' : 'http://foobar'},
            self.nonHardCodedAuthorizeEndpoint
        )

        responseOptions = { 'authority' : self.nonHardCodedAuthority }
        response = util.create_response(responseOptions)
        wireResponse = response['wireResponse']

        util.setup_expected_client_cred_token_request_response(200, wireResponse, self.nonHardCodedAuthority)

        context = adal.AuthenticationContext(self.nonHardCodedAuthority)
        token_response = context.acquire_token_with_client_credentials(
             response['resource'], cp['clientId'], cp['clientSecret'])
        self.assertTrue(
            util.is_match_token_response(response['cachedResponse'], token_response),
            'The response does not match what was expected.: ' + str(token_response)
        )

    def performStaticInstanceDiscovery(self, authorityHost):
        hardCodedAuthority = 'https://' + authorityHost + '/' + cp['tenant']

        responseOptions = {
            'authority' : hardCodedAuthority
        }
        response = util.create_response(responseOptions)
        wireResponse = response['wireResponse']
        tokenRequest = util.setup_expected_client_cred_token_request_response(200, wireResponse, hardCodedAuthority)

        context = adal.AuthenticationContext(hardCodedAuthority)
        token_response = context.acquire_token_with_client_credentials(
             response['resource'], cp['clientId'], cp['clientSecret'])

        self.assertTrue(
            util.is_match_token_response(response['cachedResponse'], token_response),
            'The response does not match what was expected.: ' + str(token_response)
        )


    @httpretty.activate
    def test_success_static_instance_discovery(self):

        self.performStaticInstanceDiscovery('login.microsoftonline.com')
        self.performStaticInstanceDiscovery('login.windows.net')
        self.performStaticInstanceDiscovery('login.chinacloudapi.cn')
        self.performStaticInstanceDiscovery('login-us.microsoftonline.com')


    @httpretty.activate
    def test_http_error(self):
        util.setup_expected_instance_discovery_request(500, cp['authorityHosts']['global'], None, self.nonHardCodedAuthorizeEndpoint)

        with six.assertRaisesRegex(self, Exception, '500'):
            context = adal.AuthenticationContext(self.nonHardCodedAuthority)
            token_response = context.acquire_token_with_client_credentials(
                 cp['resource'], cp['clientId'], cp['clientSecret'])

    @httpretty.activate
    def test_validation_error(self):
        returnDoc = { 'error' : 'invalid_instance', 'error_description' : 'the instance was invalid' }
        util.setup_expected_instance_discovery_request(400, cp['authorityHosts']['global'], returnDoc, self.nonHardCodedAuthorizeEndpoint)

        with six.assertRaisesRegex(self, Exception, 'instance was invalid'):
            context = adal.AuthenticationContext(self.nonHardCodedAuthority)
            token_response = context.acquire_token_with_client_credentials(
                 cp['resource'], cp['clientId'], cp['clientSecret'])

    @httpretty.activate
    def test_validation_off(self):
        instanceDiscoveryRequest = util.setup_expected_instance_discovery_request(
            200,
            cp['authorityHosts']['global'],
            {'tenant_discovery_endpoint' : 'http://foobar'},
            self.nonHardCodedAuthorizeEndpoint
        )

        responseOptions = { 'authority' : self.nonHardCodedAuthority}
        response = util.create_response(responseOptions)
        wireResponse = response['wireResponse']

        util.setup_expected_client_cred_token_request_response(200, wireResponse, self.nonHardCodedAuthority)

        context = adal.AuthenticationContext(self.nonHardCodedAuthority)
        token_response = context.acquire_token_with_client_credentials(
             response['resource'], cp['clientId'], cp['clientSecret'])
        self.assertTrue(
            util.is_match_token_response(response['cachedResponse'], token_response),
            'The response does not match what was expected.: ' + str(token_response)
        )


    @httpretty.activate
    def test_bad_url_not_https(self):
        with six.assertRaisesRegex(self, ValueError, "The authority url must be an https endpoint\."):
            context = AuthenticationContext('http://this.is.not.https.com/mytenant.com')

    @httpretty.activate
    def test_bad_url_has_query(self):
        with six.assertRaisesRegex(self, ValueError, "The authority url must not have a query string\."):
            context = AuthenticationContext(cp['authorityTenant'] + '?this=should&not=be&here=foo')

    @httpretty.activate
    def test_url_extra_path_elements(self):
        util.setup_expected_instance_discovery_request(200,
            cp['authorityHosts']['global'],
            {
                'tenant_discovery_endpoint' : 'http://foobar'
            },
            self.nonHardCodedAuthorizeEndpoint)

        authority_url = self.nonHardCodedAuthority + '/extra/path'
        authority = Authority(authority_url, True)
        obj = util.create_empty_adal_object()

        authority.validate(obj['call_context'])
        req = httpretty.last_request()
        util.match_standard_request_headers(req)

if __name__ == '__main__':
    unittest.main()
