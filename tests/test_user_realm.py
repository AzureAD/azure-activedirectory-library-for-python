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

import sys
import requests
import httpretty

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    from unittest import mock
except ImportError:
    import mock

try:
    from urllib.parse import urlparse, quote
except ImportError:
    from urlparse import urlparse
    from urllib import quote

import adal
from tests import util
from tests.util import parameters as cp

class TestUserRealm(unittest.TestCase):

    def setUp(self):
        self.authority = 'https://login.windows.net'
        self.user = 'test@federatedtenant-com'

        user_realm_path = cp['userRealmPathTemplate'].replace('<user>', quote(self.user, safe='~()*!.\''))
        query = 'api-version=1.0'
        self.testUrl = self.authority + user_realm_path + '?' + query

        return super(TestUserRealm, self).setUp()

    @httpretty.activate
    def test_happy_path_federated(self):

        user_realm_response = '{\"account_type\":\"Federated\",\"federation_protocol\":\"wstrust\",\"federation_metadata_url\":\"https://adfs.federatedtenant.com/adfs/services/trust/mex\",\"federation_active_auth_url\":\"https://adfs.federatedtenant.com/adfs/services/trust/2005/usernamemixed\",\"ver\":\"0.8\"}'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        try:
            user_realm.discover()
            self.assertEqual(user_realm.federation_metadata_url, 'https://adfs.federatedtenant.com/adfs/services/trust/mex',
                             'Returned Mex URL does not match expected value: {0}'.format(user_realm.federation_metadata_url))
            self.assertAlmostEqual(user_realm.federation_active_auth_url, 'https://adfs.federatedtenant.com/adfs/services/trust/2005/usernamemixed',
                                   'Returned active auth URL does not match expected value: {0}'.format(user_realm.federation_active_auth_url))
        except Exception as exp:
            self.assertIsNone(exp, "Error raised during function: {0}".format(exp))

        util.match_standard_request_headers(httpretty.last_request())

    @httpretty.activate
    def test_negative_wrong_field(self):

        user_realm_response = '{\"account_type\":\"Manageddf\",\"federation_protocol\":\"SAML20fgfg\",\"federation_metadata\":\"https://adfs.federatedtenant.com/adfs/services/trust/mex\",\"federation_active_auth_url\":\"https://adfs.federatedtenant.com/adfs/services/trust/2005/usernamemixed\",\"version\":\"0.8\"}'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        try:
            user_realm.discover()
        except Exception as exp:
            receivedException = True
            pass
        finally:
            self.assertTrue(receivedException,'Did not receive expected error')
        util.match_standard_request_headers(httpretty.last_request())

    @httpretty.activate
    def test_negative_no_root(self):

        user_realm_response = 'noroot'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        try:
            user_realm.discover()
        except Exception as exp:
            receivedException = True
            pass
        finally:
            self.assertTrue(receivedException,'Did not receive expected error')
        util.match_standard_request_headers(httpretty.last_request())

    @httpretty.activate
    def test_negative_empty_json(self):

        user_realm_response = '{}'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        try:
            user_realm.discover()
        except Exception as exp:
            receivedException = True
            pass
        finally:
            self.assertTrue(receivedException,'Did not receive expected error')
        util.match_standard_request_headers(httpretty.last_request())

    @httpretty.activate
    def test_negative_fed_err(self):

        user_realm_response = '{\"account_type\":\"Federated\",\"federation_protocol\":\"wstrustww\",\"federation_metadata_url\":\"https://adfs.federatedtenant.com/adfs/services/trust/mex\",\"federation_active_auth_url\":\"https://adfs.federatedtenant.com/adfs/services/trust/2005/usernamemixed\",\"ver\":\"0.8\"}'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        try:
            user_realm.discover()
        except Exception as exp:
            receivedException = True
            pass
        finally:
            self.assertTrue(receivedException,'Did not receive expected error')
        util.match_standard_request_headers(httpretty.last_request())

if __name__ == '__main__':
    unittest.main()
