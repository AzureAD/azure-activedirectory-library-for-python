import unittest
from adal.authentication_context import AuthenticationContext
from tests import util
from tests.util import parameters as cp
import httpretty

class TestRefreshToken(unittest.TestCase):
    def setUp(self):
        self.response_options = { 'refreshedRefresh' : True }
        self.response = util.create_response(self.response_options)
        self.wire_response = self.response['wireResponse']

    @staticmethod
    def _callback(err, tokenResponse):
        if not err:
            self.assertEqual(
                util.is_match_token_response(response['decodedResponse'], tokenResponse), 
                'The response did not match what was expected: ' + JSON.stringify(tokenResponse)
            )
    
    @httpretty.activate
    def test_happy_path_no_resource(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'])
        context = AuthenticationContext(cp['authorityTenant'])
        context.acquire_token_with_refresh_token(cp['refreshToken'], cp['clientId'], None, None, TestRefreshToken._callback)

    @httpretty.activate
    def test_happy_path_with_resource(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], self.response['resource'])
        context = AuthenticationContext(cp['authorityTenant'])
        context.acquire_token_with_refresh_token(cp['refreshToken'], cp['clientId'], None, cp['resource'], TestRefreshToken._callback)

    @httpretty.activate
    def test_happy_path_no_resource_client_secret(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], None, cp['clientSecret'])
        context = AuthenticationContext(cp['authorityTenant'])
        context.acquire_token_with_refresh_token(cp['refreshToken'], cp['clientId'], cp['clientSecret'], None, TestRefreshToken._callback)

    @httpretty.activate
    def test_happy_path_with_resource_client_secret(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], self.response['resource'], cp['clientSecret'])
        context = AuthenticationContext(cp['authorityTenant'])
        context.acquire_token_with_refresh_token(cp['refreshToken'], cp['clientId'], cp['clientSecret'], cp['resource'], TestRefreshToken._callback)  

    @httpretty.activate
    def test_happy_path_no_resource_legacy(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'])
        context = AuthenticationContext(cp['authorityTenant'])
        context.acquire_token_with_refresh_token(cp['refreshToken'], cp['clientId'], None, TestRefreshToken._callback) 

    @httpretty.activate
    def test_happy_path_with_resource_legacy(self):
        tokenRequest = util.setup_expected_refresh_token_request_response(200, self.wire_response, self.response['authority'], self.response['resource'])
        context = AuthenticationContext(cp['authorityTenant'])
        context.acquire_token_with_refresh_token(cp['refreshToken'], cp['clientId'], cp['resource'], TestRefreshToken._callback) 

if __name__ == '__main__':
    unittest.main()

