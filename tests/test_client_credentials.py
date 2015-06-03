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
        ''' TODO: Test Failing as of 2015/06/03 and needs to be completed. '''
        response_options = { 'noRefresh' : True }
        response = util.create_response(response_options)
        token_request = util.setup_expected_client_cred_token_request_response(200, response['wireResponse'])

        context = AuthenticationContext(cp['authUrl'])

        def callback(err, token_response):
            if err:
                self.fail('Expected Success:' + str(err))
            
            self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 'The response did not match what was expected')

        context.acquire_token_with_client_credentials(response['resource'], cp['clientId'], cp['clientSecret'], callback)
        
    @httpretty.activate
    def test_happy_path_cached_token(self):
        ''' TODO: Test Failing as of 2015/06/03 and needs to be completed. '''
        '''
        Tests happy-path followed by an additional call to acquire_token_with_client_credentials that should
        be served from the cache.
        '''
        response_options = { 'noRefresh' : True }
        response = util.create_response(response_options)
        token_request = util.setup_expected_client_cred_token_request_response(200, response['wireResponse'])

        context = AuthenticationContext(cp['authUrl'])

        def callback(err, token_response):
            if err:
                self.fail('Expected Success:' + str(err))
            
            self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 'The response did not match what was expected')

        context.acquire_token_with_client_credentials(response['resource'], cp['clientId'], cp['clientSecret'], callback)
       
        context.acquire_token_with_client_credentials(response['resource'], cp['clientId'], cp['clientSecret'], callback)
    
    @httpretty.activate
    def test_happy_path_cached_token_2(self):
        ''' TODO: Test Failing as of 2015/06/03 and needs to be completed. '''
        '''
        Tests happy path plus a call to the cache only function acquireToken which should find the token from the
        previous call to acquire_token_with_client_credentials.
        '''
        response_options = { 'noRefresh' : True }
        response = util.create_response(response_options)
        token_request = util.setup_expected_client_cred_token_request_response(200, response['wireResponse'])

        context = AuthenticationContext(cp['authUrl'])

        def callback(err, token_response):
            if err:
                self.fail('Expected Success:' + str(err))
            
            self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 'The response did not match what was expected')

        context.acquire_token_with_client_credentials(response['resource'], cp['clientId'], cp['clientSecret'], callback)

        none_user = None
        context2 = AuthenticationContext(cp['authUrl'])
        context2.acquire_token(response['resource'], none_user, cp['clientId'], callback)
    
    def test_no_callback(self):
        context = AuthenticationContext(cp['authorityTenant'])
        
        with self.assertRaisesRegex(TypeError, "missing 1 required positional argument: 'callback'"):
            context.acquire_token_with_client_credentials(cp['resource'], cp['clientId'], cp['clientSecret'])

    def test_no_arguments(self):
        context = AuthenticationContext(cp['authorityTenant'])

        def callback(err):
            self.assertTrue(err, 'Did not receive expected error.')
            self.assertIn('parameter', err.args[0], 'Error was not specific to a parameter:' + err.args[0])

        context.acquire_token_with_client_credentials(None, None, None, callback)
          
    def test_no_client_secret(self):
        context = AuthenticationContext(cp['authorityTenant'])

        def callback(err):
            self.assertTrue(err, 'Did not receive expected error.')
            self.assertIn('parameter', err.args[0], 'Error was not specific to a parameter:' + err.args[0])

        context.acquire_token_with_client_credentials(cp['resource'], cp['clientId'], None, callback)
        
    def test_no_client_id(self):
        context = AuthenticationContext(cp['authorityTenant'])

        def callback(err):
            self.assertTrue(err, 'Did not receive expected error.')
            self.assertIn('parameter', err.args[0], 'Error was not specific to a parameter:' + err.args[0])

        context.acquire_token_with_client_credentials(cp['resource'], None, cp['clientSecret'], callback)
        
    def test_no_resource(self):
        context = AuthenticationContext(cp['authorityTenant'])

        def callback(err):
            self.assertTrue(err, 'Did not receive expected error.')
            self.assertIn('parameter', err.args[0], 'Error was not specific to a parameter:' + err.args[0])

        context.acquire_token_with_client_credentials(None, cp['clientId'], cp['clientSecret'], callback)
    
    @httpretty.activate
    def test_http_error(self):
        ''' TODO: Test Failing as of 2015/06/03 and needs to be completed. '''
        tokenRequest = util.setup_expected_client_cred_token_request_response(403)
        context = AuthenticationContext(cp['authUrl'])

        def callback(err, tokenResponse):
            self.assertTrue(err, 'Did not receive expected error.')
            self.assertFalse(tokenResponse, 'did not expect a token response')
            self.assertIn('parameter', err.args[0], 'Error was not specific to a parameter:' + err.args[0])

        context.acquire_token_with_client_credentials(cp['resource'], cp['clientId'], cp['clientSecret'], callback)
    
    @httpretty.activate
    def test_oauth_error(self):
        ''' TODO: Test Failing as of 2015/06/03 and needs to be completed. '''
        errorResponse = {
          'error' : 'invalid_client',
          'error_description' : 'This is a test error description',
          'error_uri' : 'http://errordescription.com/invalid_client.html'
        }

        tokenRequest = util.setup_expected_client_cred_token_request_response(400, errorResponse)

        context = AuthenticationContext(cp['authUrl'])

        def callback(err, tokenResponse):
            self.assertTrue(err, 'No error was returned when one was expected.')
            
            message = 'Get Token request returned http error: 400 and server response: '
            self.assertIn(message, err.args[0])

            returnedResponse = json.loads(err.args[0][len(message):])
            self.assertDictEqual(errorResponse, returnedResponse, 'The response did not match what was expected')

        context.acquire_token_with_client_credentials(cp['resource'], cp['clientId'], cp['clientSecret'], callback)
    
    @httpretty.activate
    def test_error_with_junk_return(self):
        junkResponse = 'This is not properly formated return value.'

        tokenRequest = util.setup_expected_client_cred_token_request_response(400, junkResponse)

        context = AuthenticationContext(cp['authUrl'])

        def callback(err, _):
            self.assertTrue(err, 'No error was returned when one was expected.')

        context.acquire_token_with_client_credentials(cp['resource'], cp['clientId'], cp['clientSecret'], callback)

    @httpretty.activate
    def test_success_with_junk_return(self):
        junkResponse = 'This is not properly formated return value.'

        tokenRequest = util.setup_expected_client_cred_token_request_response(200, junkResponse)

        context = AuthenticationContext(cp['authUrl'])

        def callback(err, _):
            self.assertTrue(err, 'No error was returned when one was expected.')

        context.acquire_token_with_client_credentials(cp['resource'], cp['clientId'], cp['clientSecret'], callback)
        
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

        context = AuthenticationContext(cp['authorityTenant'])

        def callback(err, tokenResponse):
            resetSelfSignedJwtStubs(saveProto)
            if not err:
                self.assertTrue(util.is_match_token_response(response.cachedResponse, tokenResponse), 'The response did not match what was expected')
          
        context.acquire_token_with_client_certificate(response.resource, cp['clientId'], cp['cert'], cp['certHash'], callback)
         
    def test_cert_bad_cert(self):
        ''' TODO: Test Failing as of 2015/06/03 and needs to be completed. '''
        cert = 'gobbledy'

        context = AuthenticationContext(cp['authorityTenant'])

        def callback(err):
            self.assertTrue(err, 'Did not recieve expected error.')
            self.assertIn('Failed to sign JWT', err.args[0], 'Unexpected error message' + err.args[0])

        context.acquire_token_with_client_certificate(cp['resource'], cp['clientId'], cert, cp['certHash'], callback)
        
    def test_cert_bad_thumbprint(self):
        thumbprint = 'gobbledy'

        context = AuthenticationContext(cp['authorityTenant'])

        def callback(err):
            self.assertTrue(err, 'Did not recieve expected error.')
            self.assertIn('thumbprint does not match a known format', err.args[0],'Unexpected error message' + err.args[0])

        context.acquire_token_with_client_certificate(cp['resource'], cp['clientId'], cp['cert'], thumbprint, callback)

if __name__ == '__main__':
    unittest.main()
