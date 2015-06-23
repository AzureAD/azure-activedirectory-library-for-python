import unittest

import adal
from adal.self_signed_jwt import SelfSignedJwt
from adal.authentication_context import AuthenticationContext
from tests import util

from tests.util import parameters as cp
import httpretty
import json


class TestClientCredentials(unittest.TestCase):
    def setUp(self):
        util.reset_logging()
        util.clear_static_cache()

    def tearDown(self):
        util.reset_logging()
        util.clear_static_cache()

    @httpretty.activate
    def test_happy_path(self):
        response_options = { 'noRefresh' : True }
        response = util.create_response(response_options)
        token_request = util.setup_expected_client_cred_token_request_response(200, response['wireResponse'])

        token_response = adal.acquire_token_with_client_credentials(
            cp['clientSecret'], cp['authUrl'], response['resource'], cp['clientId'])
        self.assertTrue(
            util.is_match_token_response(response['cachedResponse'], token_response), 
            'The response does not match what was expected.: ' + str(token_response)
        )
    
    def test_no_arguments(self):
        with self.assertRaisesRegex(Exception, 'parameter'):
            adal.acquire_token_with_client_credentials(None)
            
    @httpretty.activate
    def test_http_error(self):
        tokenRequest = util.setup_expected_client_cred_token_request_response(403)

        with self.assertRaisesRegex(Exception, '403'):
            adal.acquire_token_with_client_credentials(cp['clientSecret'], cp['authUrl'], cp['resource'], cp['clientId'])

    @httpretty.activate
    def test_oauth_error(self):
        errorResponse = {
          'error' : 'invalid_client',
          'error_description' : 'This is a test error description',
          'error_uri' : 'http://errordescription.com/invalid_client.html'
        }

        tokenRequest = util.setup_expected_client_cred_token_request_response(400, errorResponse)
    
        with self.assertRaisesRegex(Exception, 'Get Token request returned http error: 400 and server response:'):
            adal.acquire_token_with_client_credentials(cp['clientSecret'], cp['authUrl'], cp['resource'], cp['clientId'])

    @httpretty.activate
    def test_error_with_junk_return(self):
        junkResponse = 'This is not properly formated return value.'

        tokenRequest = util.setup_expected_client_cred_token_request_response(400, junkResponse)

        with self.assertRaises(Exception):
            adal.acquire_token_with_client_credentials(cp['clientSecret'], cp['authUrl'], cp['resource'], cp['clientId'])

    @httpretty.activate
    def test_success_with_junk_return(self):
        junkResponse = 'This is not properly formated return value.'

        tokenRequest = util.setup_expected_client_cred_token_request_response(200, junkResponse)

        with self.assertRaises(Exception):
            adal.acquire_token_with_client_credentials(cp['clientSecret'], cp['authUrl'], cp['resource'], cp['clientId'])

    def test_no_cached_token_found_error(self):
        context = AuthenticationContext(cp['authUrl'])

        def callback(err, _):
            self.assertTrue(err, 'Expected an error and non was recieved.')
            self.assertIn('not found', err.args[0], 'Returned error did not contain expected message: ' + err.args[0])

        context.acquire_token(cp['resource'], 'unknownUser', cp['clientId'], callback)
        
    def update_self_signed_jwt_stubs():
        '''
        function updateSelfSignedJwtStubs() {
            savedProto = {}
            savedProto._getDateNow = SelfSignedJwt._getDateNow
            savedProto._getNewJwtId = SelfSignedJwt._getNewJwtId

            SelfSignedJwt.prototype._getDateNow = function() { return cp['nowDate'] }
            SelfSignedJwt.prototype._getNewJwtId = function() { return cp['jwtId'] }

            return savedProto
          }
        '''
        raise NotImplementedError()

    def reset_self_signed_jwt_stubs(safe_proto):
        '''
        function resetSelfSignedJwtStubs(saveProto) {
            _.extend(SelfSignedJwt, saveProto)
          }
        '''
        raise NotImplementedError()

    # TODO TODO: setupExpectedClientAssertionTokenRequestResponse, updateSelfSignedJwtStubs
    @httpretty.activate
    def test_cert_happy_path(self):
        ''' TODO: Test Failing as of 2015/06/03 and needs to be completed. '''
        self.fail("Not Yet Impelemented.  Add Helper Functions and setup method")
        saveProto = updateSelfSignedJwtStubs()

        responseOptions = { noRefresh : true }
        response = util.create_response(responseOptions)
        tokenRequest = util.setupExpectedClientAssertionTokenRequestResponse(200, response.wireResponse, cp['authorityTenant'])

        adal.acquire_token_with_client_certificate(cp['cert'], cp['certHash'], cp['authorityTenant'], response.resource, cp['clientId'])
        resetSelfSignedJwtStubs(saveProto)
        self.assertTrue(util.is_match_token_response(response.cachedResponse, token_response), 'The response did not match what was expected')

    def test_cert_bad_cert(self):
        cert = 'gobbledy'

        with self.assertRaisesRegex(Exception, "Error:Invalid Certificate: Expected Start of Certificate to be '-----BEGIN RSA PRIVATE KEY-----'"):
            adal.acquire_token_with_client_certificate(cert, cp['certHash'], cp['authorityTenant'], cp['resource'], cp['clientId'])
        
    def test_cert_bad_thumbprint(self):
        thumbprint = 'gobbledy'

        with self.assertRaisesRegex(Exception, 'thumbprint does not match a known format'):
            adal.acquire_token_with_client_certificate(cp['cert'], thumbprint, cp['authorityTenant'], cp['resource'], cp['clientId'])

if __name__ == '__main__':
    unittest.main()
