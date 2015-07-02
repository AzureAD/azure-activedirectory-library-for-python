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
import base64
import json
import adal

try:
    from tests.config import ACQUIRE_TOKEN_WITH_USERNAME_PASSWORD as user_pass_params
    from tests.config import ACQUIRE_TOKEN_WITH_CLIENT_CREDENTIALS as client_cred_params
except:
    raise Exception("Author a config.py with values for the tests. See config_sample.py for details.")

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

    @unittest.skip('https://github.com/AzureAD/azure-activedirectory-library-for-python-priv/issues/46')
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

    @unittest.skip('https://github.com/AzureAD/azure-activedirectory-library-for-python-priv/issues/47')
    def test_acquire_token_with_client_certificate(self):
        self.fail("Not Yet Implemented")


    # Validation Methods
    def validate_keys_in_dict(self, dict, keys):
        for i in keys:
            self.assertIn(i, dict)

    def validate_token_response_username_password(self, token_response):
        self.validate_keys_in_dict(
            token_response,
            [
                'accessToken', 'expiresIn', 'expiresOn', 'familyName', 'givenName',
                'refreshToken', 'resource', 'tenantId', 'tokenType',
            ]
        )

    def validate_token_response_client_credentials(self, token_response):
        self.validate_keys_in_dict(
            token_response,
            ['accessToken', 'expiresIn', 'expiresOn', 'resource', 'tokenType']
        )

    @unittest.skip('https://github.com/AzureAD/azure-activedirectory-library-for-python-priv/issues/46')
    def validate_token_response_authorization_code(self, token_response):
        self.fail("Not Yet Implemented")

    def validate_token_response_refresh_token(self, token_response):
        self.validate_keys_in_dict(
            token_response,
            [
                'accessToken', 'expiresIn', 'expiresOn', 'refreshToken', 'resource', 'tokenType'
            ]
        )

    @unittest.skip('https://github.com/AzureAD/azure-activedirectory-library-for-python-priv/issues/47')
    def validate_token_response_client_certificate(self, token_response):
        self.fail("Not Yet Implemented")

if __name__ == '__main__':
    unittest.main()
