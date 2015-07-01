#-------------------------------------------------------------------------
#
# Copyright Microsoft Open Technologies, Inc.
#
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http: *www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
# ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
# PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
#
# See the Apache License, Version 2.0 for the specific language
# governing permissions and limitations under the License.
#
#--------------------------------------------------------------------------

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

import adal
from tests import util

from tests.util import parameters as cp

try:
    from urllib.parse import urlparse, quote

except ImportError:
    from urlparse import urlparse
    from urllib import quote

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

        def _callback(err):
            self.assertIsNone(err, "Error raised during function: {0}".format(err))
            self.assertEqual(user_realm.federation_metadata_url, 'https://adfs.federatedtenant.com/adfs/services/trust/mex',
                             'Returned Mex URL does not match expected value: {0}'.format(user_realm.federation_metadata_url))
            self.assertAlmostEqual(user_realm.federation_active_auth_url, 'https://adfs.federatedtenant.com/adfs/services/trust/2005/usernamemixed',
                                   'Returned active auth URL does not match expected value: {0}'.format(user_realm.federation_active_auth_url))
        user_realm.discover(_callback)

        util.match_standard_request_headers(httpretty.last_request())

    @httpretty.activate
    def test_negative_wrong_field(self):

        user_realm_response = '{\"account_type\":\"Manageddf\",\"federation_protocol\":\"SAML20fgfg\",\"federation_metadata\":\"https://adfs.federatedtenant.com/adfs/services/trust/mex\",\"federation_active_auth_url\":\"https://adfs.federatedtenant.com/adfs/services/trust/2005/usernamemixed\",\"version\":\"0.8\"}'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        def _callback(err):
            self.assertIsNotNone(err,'Did not receive expected error')

        user_realm.discover(_callback)
        util.match_standard_request_headers(httpretty.last_request())

    @httpretty.activate
    def test_negative_no_root(self):

        user_realm_response = 'noroot'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        def _callback(err):
            self.assertIsNotNone(err,'Did not receive expected error')

        user_realm.discover(_callback)
        util.match_standard_request_headers(httpretty.last_request())

    @httpretty.activate
    def test_negative_empty_json(self):

        user_realm_response = '{}'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        def _callback(err):
            self.assertIsNotNone(err,'Did not receive expected error')

        user_realm.discover(_callback)
        util.match_standard_request_headers(httpretty.last_request())

    @httpretty.activate
    def test_negative_fed_err(self):

        user_realm_response = '{\"account_type\":\"Federated\",\"federation_protocol\":\"wstrustww\",\"federation_metadata_url\":\"https://adfs.federatedtenant.com/adfs/services/trust/mex\",\"federation_active_auth_url\":\"https://adfs.federatedtenant.com/adfs/services/trust/2005/usernamemixed\",\"ver\":\"0.8\"}'

        httpretty.register_uri(httpretty.GET, uri=self.testUrl, body=user_realm_response, status=200)
        user_realm = adal.user_realm.UserRealm(cp['callContext'], self.user, self.authority)

        def _callback(err):
            self.assertIsNotNone(err,'Did not receive expected error')

        user_realm.discover(_callback)
        util.match_standard_request_headers(httpretty.last_request())

if __name__ == '__main__':
    unittest.main()
