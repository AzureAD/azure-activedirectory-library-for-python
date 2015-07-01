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
from adal.authority import Authority
from adal import log
from adal.authentication_context import AuthenticationContext

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

        responseOptions = { 'authority' : self.nonHardCodedAuthority}
        response = util.create_response(responseOptions)
        wireResponse = response['wireResponse']

        util.setup_expected_client_cred_token_request_response(200, wireResponse, self.nonHardCodedAuthority)

        token_response = adal.acquire_token_with_client_credentials(
            self.nonHardCodedAuthority, cp['clientId'], cp['clientSecret'], response['resource'])
        self.assertTrue(
            util.is_match_token_response(response['cachedResponse'], token_response),
            'The response does not match what was expected.: ' + str(token_response)
        )

    def performStaticInstanceDiscovery(self, authorityHost, callback):
        hardCodedAuthority = 'https://' + authorityHost + '/' + cp['tenant']

        responseOptions = {
            'authority' : hardCodedAuthority
        }
        response = util.create_response(responseOptions)
        wireResponse = response['wireResponse']
        tokenRequest = util.setup_expected_client_cred_token_request_response(200, wireResponse, hardCodedAuthority)

        token_response = adal.acquire_token_with_client_credentials(
            hardCodedAuthority, cp['clientId'], cp['clientSecret'], response['resource'])

        self.assertTrue(
            util.is_match_token_response(response['cachedResponse'], token_response),
            'The response does not match what was expected.: ' + str(token_response)
        )


    @httpretty.activate
    def test_success_static_instance_discovery(self):
        def callback(err):
            if err:
                raise Exception(err)

        self.performStaticInstanceDiscovery('login.microsoftonline.com', callback)
        self.performStaticInstanceDiscovery('login.windows.net', callback)
        self.performStaticInstanceDiscovery('login.chinacloudapi.cn', callback)
        self.performStaticInstanceDiscovery('login.cloudgovapi.us', callback)


    @httpretty.activate
    def test_http_error(self):
        util.setup_expected_instance_discovery_request(500, cp['authorityHosts']['global'], None, self.nonHardCodedAuthorizeEndpoint)

        with self.assertRaisesRegex(Exception, '500'):
            token_response = adal.acquire_token_with_client_credentials(
                self.nonHardCodedAuthority, cp['clientId'], cp['clientSecret'], cp['resource'])

    @httpretty.activate
    def test_validation_error(self):
        returnDoc = { 'error' : 'invalid_instance', 'error_description' : 'the instance was invalid' }
        util.setup_expected_instance_discovery_request(400, cp['authorityHosts']['global'], returnDoc, self.nonHardCodedAuthorizeEndpoint)

        with self.assertRaisesRegex(Exception, 'instance was invalid'):
            token_response = adal.acquire_token_with_client_credentials(
                self.nonHardCodedAuthority, cp['clientId'], cp['clientSecret'], cp['resource'])

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

        token_response = adal.acquire_token_with_client_credentials(
            self.nonHardCodedAuthority, cp['clientId'], cp['clientSecret'], response['resource'], validate_authority = False)
        self.assertTrue(
            util.is_match_token_response(response['cachedResponse'], token_response),
            'The response does not match what was expected.: ' + str(token_response)
        )


    @httpretty.activate
    def test_bad_url_not_https(self):
        with self.assertRaisesRegex(ValueError, "The authority url must be an https endpoint\."):
            context = AuthenticationContext('http://this.is.not.https.com/mytenant.com')

    @httpretty.activate
    def test_bad_url_has_query(self):
        with self.assertRaisesRegex(ValueError, "The authority url must not have a query string\."):
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

        def callback(err):
            if err:
                self.assertFalse(err, 'Received unexpected error: ' + err.args[0])
            req = httpretty.last_request()
            util.match_standard_request_headers(req)

        authority.validate(obj['call_context'], callback)

if __name__ == '__main__':
    unittest.main()
