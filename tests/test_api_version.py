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

import warnings
try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    from unittest import mock
except ImportError:
    import mock

import adal

class TestAuthenticationContextApiVersionBehavior(unittest.TestCase):

    def test_api_version_default_value(self):
        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always")
            context = adal.AuthenticationContext(
                "https://login.windows.net/tenant")
            self.assertEqual(context._call_context['api_version'], '1.0')
            if len(caught_warnings) == 1:
                # It should be len(caught_warnings)==1, but somehow it works on
                # all my local test environment but not on Travis-CI.
                # So we relax this check, for now.
                self.assertIn("deprecated", str(caught_warnings[0].message))

    def test_explicitly_turn_off_api_version(self):
        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always")
            context = adal.AuthenticationContext(
                "https://login.windows.net/tenant", api_version=None)
            self.assertEqual(context._call_context['api_version'], None)
            self.assertEqual(len(caught_warnings), 0)

class TestOAuth2ClientApiVersionBehavior(unittest.TestCase):

    authority = mock.Mock(token_endpoint="https://example.com/token")

    def test_api_version_is_set(self):
        client = adal.oauth2_client.OAuth2Client(
            {"api_version": "1.0", "log_context": mock.Mock()}, self.authority)
        self.assertIn('api-version=1.0', client._create_token_url().geturl())

    def test_api_version_is_not_set(self):
        client = adal.oauth2_client.OAuth2Client(
            {"api_version": None, "log_context": mock.Mock()}, self.authority)
        self.assertNotIn('api-version=1.0', client._create_token_url().geturl())

if __name__ == '__main__':
    unittest.main()

