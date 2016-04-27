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

import unittest
import json
import httpretty
import six

import adal
from adal.self_signed_jwt import SelfSignedJwt
from adal.authentication_context import AuthenticationContext
from tests import util
from tests.util import parameters as cp

class TestClientCredentials(unittest.TestCase):
    def setUp(self):
        util.reset_logging()
        util.clear_static_cache()

    def tearDown(self):
        util.reset_logging()
        util.clear_static_cache()

    @httpretty.activate
    def test_happy_path(self):
        response_options = { 'noRefresh' : True, 'tokenEndpoint': True }
        response = util.create_response(response_options)
        token_request = util.setup_expected_client_cred_token_request_response(200, response['wireResponse'])

        context = adal.AuthenticationContext(cp['authUrl'])
        token_response = context.acquire_token_with_client_credentials(
             response['resource'], cp['clientId'], cp['clientSecret'])
        self.assertTrue(
            util.is_match_token_response(response['cachedResponse'], token_response),
            'The response does not match what was expected.: ' + str(token_response)
        )

    @httpretty.activate
    def test_http_error(self):
        tokenRequest = util.setup_expected_client_cred_token_request_response(403)

        with six.assertRaisesRegex(self, Exception, '403'):
            context = adal.AuthenticationContext(cp['authUrl'])
            token_response = context.acquire_token_with_client_credentials(
                 cp['resource'], cp['clientId'], cp['clientSecret'])

    @httpretty.activate
    def test_oauth_error(self):
        errorResponse = {
          'error' : 'invalid_client',
          'error_description' : 'This is a test error description',
          'error_uri' : 'http://errordescription.com/invalid_client.html'
        }

        tokenRequest = util.setup_expected_client_cred_token_request_response(400, errorResponse)

        with six.assertRaisesRegex(self, Exception, 'Get Token request returned http error: 400 and server response:'):
            context = adal.AuthenticationContext(cp['authUrl'])
            token_response = context.acquire_token_with_client_credentials(
                 cp['resource'], cp['clientId'], cp['clientSecret'])

    @httpretty.activate
    def test_error_with_junk_return(self):
        junkResponse = 'This is not properly formated return value.'

        tokenRequest = util.setup_expected_client_cred_token_request_response(400, junkResponse)

        with self.assertRaises(Exception):
            context = adal.AuthenticationContext(cp['authUrl'])
            token_response = context.acquire_token_with_client_credentials(
                 cp['resource'], cp['clientId'], cp['clientSecret'])

    @httpretty.activate
    def test_success_with_junk_return(self):
        junkResponse = 'This is not properly formated return value.'

        tokenRequest = util.setup_expected_client_cred_token_request_response(200, junkResponse)

        with self.assertRaises(Exception):
            context = adal.AuthenticationContext(cp['authUrl'])
            token_response = context.acquire_token_with_client_credentials(
                 cp['resource'], cp['clientId'], cp['clientSecret'])

    def test_no_cached_token_found_error(self):
        context = AuthenticationContext(cp['authUrl'])

        try:
            context.acquire_token(cp['resource'], 'unknownUser', cp['clientId'])
        except Exception as err:
            self.assertTrue(err, 'Expected an error and non was recieved.')
            self.assertIn('not found', err.args[0], 'Returned error did not contain expected message: ' + err.args[0])


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

    @unittest.skip('https://github.com/AzureAD/azure-activedirectory-library-for-python-priv/issues/20')
    # TODO TODO: setupExpectedClientAssertionTokenRequestResponse, updateSelfSignedJwtStubs
    @httpretty.activate
    def test_cert_happy_path(self):
        ''' TODO: Test Failing as of 2015/06/03 and needs to be completed. '''
        self.fail("Not Yet Impelemented.  Add Helper Functions and setup method")
        saveProto = updateSelfSignedJwtStubs()

        responseOptions = { noRefresh : true }
        response = util.create_response(responseOptions)
        tokenRequest = util.setupExpectedClientAssertionTokenRequestResponse(200, response.wireResponse, cp['authorityTenant'])
        context = adal.AuthenticationContext(cp['authorityTenant'])

        context.acquire_token_with_client_certificate(response.resource, cp['clientId'], cp['cert'], cp['certHash'])

        resetSelfSignedJwtStubs(saveProto)
        self.assertTrue(util.is_match_token_response(response.cachedResponse, token_response), 'The response did not match what was expected')

    def test_cert_bad_cert(self):
        cert = 'gobbledy'
        context = adal.AuthenticationContext(cp['authorityTenant'])

        with six.assertRaisesRegex(self, Exception, "Error:Invalid Certificate: Expected Start of Certificate to be '-----BEGIN RSA PRIVATE KEY-----'"):
            context.acquire_token_with_client_certificate(cp['resource'], cp['clientId'], cert, cp['certHash'])

    def test_cert_bad_thumbprint(self):
        thumbprint = 'gobbledy'
        context = adal.AuthenticationContext(cp['authorityTenant'])

        with six.assertRaisesRegex(self, Exception, 'thumbprint does not match a known format'):
            context.acquire_token_with_client_certificate( cp['resource'], cp['clientId'], cp['cert'], thumbprint)


if __name__ == '__main__':
    unittest.main()
