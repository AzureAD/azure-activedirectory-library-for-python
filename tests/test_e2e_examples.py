#-------------------------------------------------------------------------
# Copyright (c) Microsoft. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#--------------------------------------------------------------------------
import unittest
from adal.authentication_context import AuthenticationContext
import base64
import json
import adal

try:
    from tests.config import acquire_token_with_username_password as user_pass_params
    from tests.config import acquire_token_with_client_credentials as client_cred_params
except:
    raise Exception("Author a config.py with values for the tests.  This file is not checked in.")

class TestE2EExamples(unittest.TestCase):

    def setUp(self):
        self.assertIsNotNone(user_pass_params['password'], "This test cannot work without you adding a password")
        return super().setUp()

    def test_acquire_token_with_user_pass_defaults(self):
        authority = user_pass_params['authorityHostUrl'] + '/' + user_pass_params['tenant']
        token_response = adal.acquire_token_with_username_password(
            authority, user_pass_params['username'], user_pass_params['password'])
        self.validate_token_response_username_password(token_response)

    def test_acquire_token_with_user_pass_explicit(self):
        resource = '00000002-0000-0000-c000-000000000000'
        client_id_xplat = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        authority = user_pass_params['authorityHostUrl'] + '/' + user_pass_params['tenant']

        token_response = adal.acquire_token_with_username_password(
            authority, user_pass_params['username'], user_pass_params['password'],
            client_id_xplat, resource)
        self.validate_token_response_username_password(token_response)
  
    def test_acquire_token_with_client_creds(self):
        token_response = adal.acquire_token_with_client_credentials(
            client_cred_params['authority'], 
            client_cred_params['client_id'], 
            client_cred_params['secret'])
        self.validate_token_response_client_credentials(token_response)

    def test_acquire_token_with_authorization_code(self):
        self.fail("Not Yet Implemented")

    def test_acquire_token_with_refresh_token(self):
        authority = user_pass_params['authorityHostUrl'] + '/' + user_pass_params['tenant']
        
        # Get token using username password first
        token_response = adal.acquire_token_with_username_password(
            authority, user_pass_params['username'], user_pass_params['password'])
        self.validate_token_response_username_password(token_response)

        # Use returned refresh token to acquire a new token.
        refresh_token = token_response['refreshToken']
        token_response2 = adal.acquire_token_with_refresh_token(authority, refresh_token)
        self.validate_token_response_refresh_token(token_response2)
    
    def test_acquire_token_with_client_certificate(self):
        self.fail("Not Yet Implemented")
   

    # Validation Methods
    def validate_token_response_username_password(self, token_response):
        self.assertIsNotNone(token_response)

        # token response is a dict that should have
        expected = [
            'accessToken', 'expiresIn', 'expiresOn', 'familyName', 'givenName',
            'isUserIdDisplayable', 'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'
        ]
        for i in expected:
            self.assertIsNotNone(token_response.get(i), '{} is an expected item in the token response'.format(i))

    def validate_token_response_client_credentials(self, token_response):
        self.assertIsNotNone(token_response)

        # token response is a dict that should have
        expected = [
            'accessToken', 'expiresIn', 'expiresOn', 'resource', 'tokenType'
        ]
        for i in expected:
            self.assertIsNotNone(token_response.get(i), '{} is an expected item in the token response'.format(i))

    def validate_token_response_authorization_code(self, token_response):
        self.fail("Not Yet Implemented")

    def validate_token_response_refresh_token(self, token_response):
        self.assertIsNotNone(token_response)

        # token response is a dict that should have
        expected = [
            'accessToken', 'expiresIn', 'expiresOn', 'refreshToken', 'resource', 'tokenType'
        ]
        for i in expected:
            self.assertIsNotNone(token_response.get(i), '{} is an expected item in the token response'.format(i))

    def validate_token_response_client_certificate(self, token_response):
        self.fail("Not Yet Implemented")

if __name__ == '__main__':
    unittest.main()
