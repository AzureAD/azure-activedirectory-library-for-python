import sys
import requests
import httpretty
import json

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import adal
from adal.authentication_context import AuthenticationContext
from tests import util
from tests.util import parameters as cp

class TestRefreshToken(unittest.TestCase):
    def setUp(self):
        self.response_options = { 'refreshedRefresh' : True }
        self.response = util.create_response(self.response_options)
        self.wire_response = self.response['wireResponse']

    def _callback(self, err, token_response):
        self.assertFalse(err, 'Unexpected Err:{}'.format(err))
        self.assertTrue(
            util.is_match_token_response(self.response['decodedResponse'], token_response),
            'The response did not match what was expected: ' + str(token_response)
        )

    @httpretty.activate
    def test_happy_path_no_resource_no_client_secret(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'])
        adal.acquire_token_with_refresh_token(cp['authorityTenant'], cp['refreshToken'], cp['clientId'], None, None)

    @httpretty.activate
    def test_happy_path_with_resource_no_client_secret(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], self.response['resource'])
        adal.acquire_token_with_refresh_token(cp['authorityTenant'], cp['refreshToken'], cp['clientId'], None, cp['resource'])

    @httpretty.activate
    def test_happy_path_no_resource_client_secret(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], None, cp['clientSecret'])
        adal.acquire_token_with_refresh_token(cp['authorityTenant'], cp['refreshToken'], cp['clientId'], cp['clientSecret'], None)

    @httpretty.activate
    def test_happy_path_with_resource_client_secret(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], self.response['resource'], cp['clientSecret'])
        adal.acquire_token_with_refresh_token(cp['authorityTenant'], cp['refreshToken'], cp['clientId'], cp['clientSecret'], cp['resource'])

if __name__ == '__main__':
    unittest.main()
