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
import logging
import json
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import sys
import requests
import httpretty
from adal import oauth2_client

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    from unittest import mock
except ImportError:
    import mock

from tests import util
from tests.util import parameters as cp

import adal
from adal.authentication_context import AuthenticationContext
from adal.mex import Mex
from adal.token_request import TokenRequest
from adal.oauth2_client import OAuth2Client
from adal.user_realm import UserRealm
from adal.wstrust_response import WSTrustResponse
from adal.wstrust_request import WSTrustRequest
from adal import log
from adal.authority import Authority
from adal.constants import AADConstants

try:
    from urllib.parse import urlparse, urlencode
except ImportError:
    from urllib import urlencode
    from urlparse import urlparse

class TestUsernamePassword(unittest.TestCase):

    def setUp(self):
        util.reset_logging()
        util.clear_static_cache()

    def tearDown(self):
        util.reset_logging()
        util.clear_static_cache()

    def setup_expected_oauth_assertion_request(self, response):
        with open(cp['AssertionFile']) as assertFile:
            assertion = assertFile.read()

        queryParameters = {}
        queryParameters['grant_type'] = 'urn:ietf:params:oauth:grant-type:saml1_1-bearer'
        queryParameters['client_id'] = response['clientId']
        queryParameters['resource'] = response['resource']
        queryParameters['assertion'] = assertion
        queryParameters['scope'] = 'openid'

        return util.setup_expected_oauth_response(queryParameters, cp['tokenUrlPath'], 200, response['wireResponse'], cp['authority'])

    def setup_expected_username_password_request_response(self, httpCode, returnDoc, authorityEndpoint, isAdfs = False):
        queryParameters = {}
        queryParameters['grant_type'] = 'password'
        queryParameters['client_id'] = cp['clientId']
        queryParameters['resource'] = cp['resource']
        queryParameters['username'] = cp['username']
        queryParameters['password'] = cp['password']
        queryParameters['scope'] = 'openid'

        query = urlencode(queryParameters)
        token_path = cp['tokenPath']
        if isAdfs:
            token_path = cp['tokenPath'] # TODO: figure out to match w/o query + cp['extraQP']

        url = '{}{}'.format(authorityEndpoint, token_path)
        #'https://login.windows.net/rrandallaad1.onmicrosoft.com/oauth2/token?slice=testslice&api-version=1.0'
        httpretty.register_uri(httpretty.POST, url, json.dumps(returnDoc), status = httpCode, content_type = 'text/json')

    @httpretty.activate
    def test_happy_path_adfs_authority(self):
        adfsAuthority = 'https://contoso.com/adfs'
        responseOptions = { 'authority' : adfsAuthority,  'mrrt' : True }
        response = util.create_response(responseOptions)
        upRequest = self.setup_expected_username_password_request_response(200, response['wireResponse'], adfsAuthority, True)

        context = adal.AuthenticationContext(adfsAuthority, False)

        #action
        token_response = context.acquire_token_with_username_password(response['resource'], cp['username'], cp['password'], cp['clientId'])

        #assert
        self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response),
               'Response did not match expected: ' + json.dumps(token_response))

    @httpretty.activate
    def test_managed_happy_path(self):
        util.setup_expected_user_realm_response_common(False)
        response = util.create_response()

        authorityUrl = response['authority']
        upRequest = self.setup_expected_username_password_request_response(200, response['wireResponse'], authorityUrl)

        context = adal.AuthenticationContext(authorityUrl)

        #action
        token_response = context.acquire_token_with_username_password(response['resource'], cp['username'],
                                                                      cp['password'], cp['clientId'])

        #assert
        self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response),
                        'Response did not match expected: ' + json.dumps(token_response))

    # Since this test is the most code intensive it will make a good test case for
    # correlation id.
    @httpretty.activate
    def test_federated_happy_path_and_correlation_id(self):
        util.setup_expected_user_realm_response_common(True)
        util.setup_expected_mex_wstrust_request_common()

        response = util.create_response()
        assertion = self.setup_expected_oauth_assertion_request(response)

        buffer = StringIO()
        handler = logging.StreamHandler(buffer)
        util.turn_on_logging(level='DEBUG', handler=handler)

        authorityUrl = response['authority']

        context = adal.AuthenticationContext(authorityUrl)
        correlation_id = '12300002-0000-0000-c000-000000000000'
        context.correlation_id = correlation_id

        #action
        token_response = context.acquire_token_with_username_password(response['resource'], cp['username'], cp['password'], cp['clientId'])
        self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 
                        'Response did not match expected: ' + json.dumps(token_response))
        
        #assert
        log_content = buffer.getvalue()
        self.assertTrue(correlation_id in log_content, 'Logging was turned on but no messages were recieved.')

    @httpretty.activate
    def test_invalid_id_token(self):
        util.setup_expected_user_realm_response_common(False)
        response = util.create_response()
        wireResponse = response['wireResponse']

        response_options = { 'noIdToken' : True }
        response = util.create_response(response_options)

        # break the id token
        idToken = wireResponse['id_token']
        idToken = idToken.replace('.', ' ')
        wireResponse['id_token'] = idToken
        authorityUrl = response['authority']
        upRequest = self.setup_expected_username_password_request_response(200, wireResponse, authorityUrl)

        context = adal.AuthenticationContext(authorityUrl)

        #action
        token_response = context.acquire_token_with_username_password(response['resource'], cp['username'], cp['password'], cp['clientId'])

        #assert
        self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 'Response did not match expected: ' + json.dumps(token_response))

    def create_mex_stub(self, usernamePasswordUrl, err=None):
        mex = Mex(cp['callContext'], '')
        if err:
            mex.discover = mock.MagicMock(side_effect=err)#TODO: verify the mock gets called
        else:
            mex.username_password_policy = {'url' : usernamePasswordUrl}
        return mex

    def create_user_realm_stub(self, protocol, accountType, mexUrl, wstrustUrl, err=None):
        userRealm = UserRealm(cp['callContext'], '', '')

        userRealm.discover = mock.MagicMock()#TODO: verify the mock gets called

        userRealm.federation_protocol = protocol
        userRealm.account_type = accountType
        userRealm.federation_metadata_url = mexUrl
        userRealm.federation_active_auth_url = wstrustUrl
        return userRealm

    def create_wstrust_request_stub(self, err, tokenType, noToken=None):
        wstrust_response = WSTrustResponse(cp['callContext'], '', '')
        wstrust_response.error_code = err
        wstrust_response.parse = mock.MagicMock()
        if not noToken:
            wstrust_response.token = b'This is a stubbed token'
            wstrust_response.token_type = tokenType

        wstrust_request = WSTrustRequest(cp['callContext'], '', '', '')

        def side_effect (username, password):
            if err:
                raise err
            return wstrust_response
        wstrust_request.acquire_token = mock.MagicMock(side_effect=side_effect)

        return wstrust_request

    def create_authentication_context_stub(self, authority):
        context = AuthenticationContext(authority, False)
        context.authority.token_endpoint = authority + cp['tokenPath']
        return context

    def create_oauth2_client_stub(self, authority, token_response, err):
        authorityObject = Authority(authority, False)
        authorityObject.token_endpoint = AADConstants.TOKEN_ENDPOINT_PATH
        authorityObject.device_code_endpoint = AADConstants.DEVICE_ENDPOINT_PATH
        client = OAuth2Client(cp['callContext'], authorityObject)

        def side_effect (oauth):
            return token_response
        client.get_token = mock.MagicMock(side_effect=side_effect)

        return client

    def stub_out_token_request_dependencies(self, tokenRequest, userRealm, mex, wstrustRequest=None, oauthClient=None):
        tokenRequest._create_user_realm_request = mock.MagicMock(return_value=userRealm)
        tokenRequest._create_mex = mock.MagicMock(return_value=mex)
        tokenRequest._create_wstrust_request = mock.MagicMock(return_value=wstrustRequest)
        tokenRequest._create_oauth2_client = mock.MagicMock(return_value=oauthClient)

    def test_federated_failed_mex(self):
        context = self.create_authentication_context_stub(cp['authorityTenant'])
        mex = self.create_mex_stub(cp['adfsWsTrust'], Exception('mex failed'))
        userRealm = self.create_user_realm_stub('wstrust', 'federated', cp['adfsMex'], cp['adfsWsTrust'])
        wstrustRequest = self.create_wstrust_request_stub(None, 'urn:oasis:names:tc:SAML:1.0:assertion')

        response = util.create_response()
        oauthClient = self.create_oauth2_client_stub(cp['authority'], response['cachedResponse'], None)

        tokenRequest = TokenRequest(cp['callContext'], context, response['clientId'], response['resource'])
        self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex, wstrustRequest, oauthClient)

        #action
        token_response = tokenRequest.get_token_with_username_password(cp['username'], cp['password'])

        #assert
        self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 'The response did not match what was expected')

    def test_federated_user_realm_returns_no_mex_endpoint_wstrust13(self):
        context = self.create_authentication_context_stub(cp['authorityTenant'])
        mex = self.create_mex_stub(cp['adfsWsTrust'])
        userRealm = self.create_user_realm_stub('wstrust', 'federated', None, cp['adfsWsTrust'])
        wstrustRequest = self.create_wstrust_request_stub(None, 'urn:oasis:names:tc:SAML:1.0:assertion')

        response = util.create_response()
        oauthClient = self.create_oauth2_client_stub(cp['authority'], response['decodedResponse'], None)

        tokenRequest = TokenRequest(cp['callContext'], context, response['clientId'], response['resource'])
        self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex, wstrustRequest, oauthClient)

        #action
        token_response = tokenRequest.get_token_with_username_password(cp['username'], cp['password'])

        #assert
        self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 'The response did not match what was expected')

    def test_federated_user_realm_returns_no_mex_endpoint_wstrust2005(self):
         context = self.create_authentication_context_stub(cp['authorityTenant'])
         mex = self.create_mex_stub(cp['adfsWsTrust2005'])
         userRealm = self.create_user_realm_stub('wstrust', 'federated', None, cp['adfsWsTrust2005'])
         wstrustRequest = self.create_wstrust_request_stub(None, 'urn:oasis:names:tc:SAML:1.0:assertion')

         response = util.create_response()
         oauthClient = self.create_oauth2_client_stub(cp['authority'], response['decodedResponse'], None)

         tokenRequest = TokenRequest(cp['callContext'], context, response['clientId'], response['resource'])
         self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex, wstrustRequest, oauthClient);

         #action
         token_response = tokenRequest.get_token_with_username_password(cp['username'], cp['password'])

         #assert
         self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 'The response did not match what was expected')

    def test_user_realm_returns_unknown_account_type(self):
        context = self.create_authentication_context_stub(cp['authorityTenant'])
        mex = self.create_mex_stub(cp['adfsWsTrust'])
        userRealm = self.create_user_realm_stub('wstrust', 'unknown', cp['adfsMex'], cp['adfsWsTrust'])

        tokenRequest = TokenRequest(cp['callContext'], context, cp['clientId'], cp['resource'])
        self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex)

        #action
        try:
            tokenRequest.get_token_with_username_password(cp['username'], cp['password'])
            self.fail('Exception not raised, when it should have been')
        except Exception as err:
            #assert
            self.assertTrue(err, 'Did not receive expected err.')
            self.assertTrue('unknown AccountType' in err.args[0], 'Did not receive expected error message.')

    def test_federated_saml2(self):
        context = self.create_authentication_context_stub(cp['authorityTenant'])
        mex = self.create_mex_stub(cp['adfsWsTrust'])
        userRealm = self.create_user_realm_stub('wstrust', 'federated', cp['adfsMex'], cp['adfsWsTrust'])
        wstrustRequest = self.create_wstrust_request_stub(None, 'urn:oasis:names:tc:SAML:2.0:assertion')

        response = util.create_response()
        oauthClient = self.create_oauth2_client_stub(cp['authority'], response['cachedResponse'], None)

        tokenRequest = TokenRequest(cp['callContext'], context, response['clientId'], response['resource'])
        self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex, wstrustRequest, oauthClient)

        #action
        token_response = tokenRequest.get_token_with_username_password(cp['username'], cp['password'])

        #assert
        self.assertTrue(util.is_match_token_response(response['cachedResponse'], token_response), 'The response did not match what was expected')

    def test_federated_unknown_token_type(self):
        context = self.create_authentication_context_stub(cp['authorityTenant'])
        mex = self.create_mex_stub(cp['adfsWsTrust'])
        userRealm = self.create_user_realm_stub('wstrust', 'federated', cp['adfsMex'], cp['adfsWsTrust'])
        wstrustRequest = self.create_wstrust_request_stub(None, 'urn:oasis:names:tc:SAML:100.0:assertion')

        response = util.create_response()
        oauthClient = self.create_oauth2_client_stub(cp['authority'], response['decodedResponse'], None)

        tokenRequest = TokenRequest(cp['callContext'], context, response['clientId'], response['resource'])
        self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex, wstrustRequest, oauthClient)

        #action
        try:
            tokenRequest.get_token_with_username_password(cp['username'], cp['password'])
            self.assertTrue(receivedException, 'Did not receive expected error')
        except Exception as err:
            #assert
            self.assertTrue('token type' in err.args[0], "Error message did not contain 'token type'. message:{}".format(err.args[0]))

    def test_federated_failed_wstrust(self):
        context = self.create_authentication_context_stub(cp['authorityTenant'])
        mex = self.create_mex_stub(cp['adfsWsTrust'])
        userRealm = self.create_user_realm_stub('wstrust', 'federated', None, cp['adfsWsTrust'])
        mock_err_msg = 'Network not available'
        wstrustRequest = self.create_wstrust_request_stub(Exception(mock_err_msg), 'urn:oasis:names:tc:SAML:1.0:assertion')

        response = util.create_response()
        oauthClient = self.create_oauth2_client_stub(cp['authority'], response['cachedResponse'], None)

        tokenRequest = TokenRequest(cp['callContext'], context, response['clientId'], response['resource'])
        self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex, wstrustRequest, oauthClient)

        #action
        try:
            tokenRequest.get_token_with_username_password(cp['username'], cp['password'])
            self.fail('Did not receive expected error')
        except Exception as exp:
            #assert
            self.assertEqual(mock_err_msg, exp.args[0])

    def test_federated_wstrust_unparseable(self):
        context = self.create_authentication_context_stub(cp['authorityTenant'])
        mex = self.create_mex_stub(cp['adfsWsTrust'])
        userRealm = self.create_user_realm_stub('wstrust', 'federated', None, cp['adfsWsTrust'])
        wstrustRequest = self.create_wstrust_request_stub(None, 'urn:oasis:names:tc:SAML:2.0:assertion', True)

        response = util.create_response()
        oauthClient = self.create_oauth2_client_stub(cp['authority'], response['decodedResponse'], None)

        tokenRequest = TokenRequest(cp['callContext'], context, response['clientId'], response['resource'])
        self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex, wstrustRequest, oauthClient)

        #action
        try:
            tokenRequest.get_token_with_username_password(cp['username'], cp['password'])
            self.fail('Did not receive expected error')
        except Exception as exp:
            #assert
            self.assertEqual('Unsuccessful RSTR.\n\terror code: None\n\tfaultMessage: None', exp.args[0])

    def test_federated_wstrust_unknown_token_type(self):
        context = self.create_authentication_context_stub(cp['authorityTenant'])
        mex = self.create_mex_stub(cp['adfsWsTrust'])
        userRealm = self.create_user_realm_stub('wstrust', 'federated', None, cp['adfsWsTrust'])
        wstrustRequest = self.create_wstrust_request_stub(None, 'urn:oasis:names:tc:SAML:100.0:assertion', True)

        response = util.create_response()
        oauthClient = self.create_oauth2_client_stub(cp['authority'], response['decodedResponse'], None)

        tokenRequest = TokenRequest(cp['callContext'], context, response['clientId'], response['resource'])
        self.stub_out_token_request_dependencies(tokenRequest, userRealm, mex, wstrustRequest, oauthClient)

        #action
        try:
            tokenRequest.get_token_with_username_password(cp['username'], cp['password'])
            self.fail(receivedException, 'Did not receive expected error')
        except Exception as exp:
            #assert
            self.assertEqual('Unsuccessful RSTR.\n\terror code: None\n\tfaultMessage: None', exp.args[0])

    def test_parse_id_token_with_unicode(self):
        client = self.create_oauth2_client_stub('https://foo/ba.onmicrosoft.com', None, None)
        encoded_token = '.eyJmYW1pbHlfbmFtZSI6Ikd1aW5lYmVydGnDqHJlIn0.'# JWT with payload = {"family_name": "Guinebertière"}
        result = client._parse_id_token(encoded_token)
        self.assertEqual(result['familyName'], u'Guinebertière')

    def test_jwt_cracking(self):
        testData = [
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.',
            {
              'header' : 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0',
              'JWSPayload' : 'eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9',
              'JWSSig' : ''
            }
          ],
          # remove header
          [
            '.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.',
            {
              'header' : '',
              'JWSPayload' : 'eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9',
              'JWSSig' : ''
            }
          ],
          # Add JWSSig
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.foobar',
            {
              'header' : 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0',
              'JWSPayload' : 'eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9',
              'JWSSig' : 'foobar'
            }
          ],
          # Remove JWS payload
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0..',
            None
          ],
          # Remove JWS payload
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0..foobar',
            None
          ],
          # JWT payload is only a space.
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0. .foobar',
            None
          ],
          # Add space
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1 mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.',
            None
          ],
          # remove first period.
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.',
            None
          ],
          # remove second period.
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9',
            None
          ],
          # prefixed space
          [
            '  eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.foobar',
            None
          ],
          # trailing space
          [
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.foobar  ',
            None
          ],
          # add section
          [
            'notsupposedtobehere.eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.foobar',
            None
          ],
          # extra stuff at beginning seperated by space.
          [
            'stuff eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.foobar',
            None
          ],
        ]

        client = self.create_oauth2_client_stub('https://foo/ba.onmicrosoft.com', None, None)
        for testCase in testData:
            testJWT = testCase[0]
            testResult = testCase[1]
            crackedJwt = client._open_jwt(testJWT)
            if testResult:
                resp = util.dicts_equal(testResult, crackedJwt)
                self.assertTrue(resp is None, 'The cracked token does not match the expected result.: {}'.format(resp))
            else:
                self.assertFalse(crackedJwt)

    @httpretty.activate
    def test_bad_int_in_response(self):
        util.setup_expected_user_realm_response_common(False)
        response = util.create_response()

        response['wireResponse']['expires_in'] = 'foo'

        upRequest = self.setup_expected_username_password_request_response(200, response['wireResponse'], response['authority'])
        authorityUrl = response['authority']
        context = adal.AuthenticationContext(authorityUrl)

        #action
        try:
            token_response = context.acquire_token_with_username_password(response['resource'], cp['username'], cp['password'], cp['clientId'])
            self.fail('Did not see expected warning message about bad expires_in field')
        except Exception as exp:
            #assert
            self.assertEqual("invalid literal for int() with base 10: 'foo'", exp.args[0])

    @httpretty.activate
    def test_bad_id_token_base64_in_response(self):
        foundWarning = False
        util.setup_expected_user_realm_response_common(False)
        response = util.create_response()
      
        log_content = StringIO()
        handler = logging.StreamHandler(log_content)
        util.turn_on_logging(level='WARNING', handler=handler)

        response['wireResponse']['id_token'] = 'aaaaaaa./+===.aaaaaa'
        expected_warn = 'The returned id_token could not be decoded: aaaaaaa./+===.aaaaaa'
        authorityUrl = response['authority'] 
        upRequest = self.setup_expected_username_password_request_response(200, response['wireResponse'], authorityUrl)

        context = adal.AuthenticationContext(authorityUrl)

        #action and verify
        self.assertRaises(UnicodeDecodeError, context.acquire_token_with_username_password, response['resource'], cp['username'], cp['password'], cp['clientId'])

    @httpretty.activate
    def test_no_token_type(self):
        util.setup_expected_user_realm_response_common(False)
        response = util.create_response()
        authorityUrl = response['authority']

        del response['wireResponse']['token_type']

        upRequest = self.setup_expected_username_password_request_response(200, response['wireResponse'], response['authority'])
        context = adal.AuthenticationContext(authorityUrl)

        #action
        try:
            context.acquire_token_with_username_password(response['resource'], cp['username'], cp['password'], cp['clientId'])
            self.fail('Did not receive expected error about missing token_type')
        except Exception as exp:
            #assert
            self.assertEqual('wire_response is missing token_type', exp.args[0])

    @httpretty.activate
    def test_no_access_token(self):
        util.setup_expected_user_realm_response_common(False)
        response = util.create_response()
        del response['wireResponse']['access_token']

        upRequest = self.setup_expected_username_password_request_response(200, response['wireResponse'], response['authority'])
        authorityUrl = response['authority']
        context = adal.AuthenticationContext(authorityUrl)

        #action
        try:
            token_response = context.acquire_token_with_username_password(response['resource'], cp['username'], cp['password'], cp['clientId'])
            self.fail('Did not receive expected error about missing token_type')
        except Exception as exp:
            #assert
            self.assertEqual('wire_response is missing access_token', exp.args[0])

if __name__ == '__main__':
    unittest.main()
