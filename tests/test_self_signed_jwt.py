import sys
import requests
import httpretty
import json
from adal.self_signed_jwt import SelfSignedJwt
from datetime import datetime
from adal.authority import Authority

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    from unittest import mock
except ImportError:
    import mock

import adal
from adal.authentication_context import AuthenticationContext
from tests import util
from tests.util import parameters as cp

class TestSelfSignedJwt(unittest.TestCase):
    testNowDate = cp['nowDate']
    testJwtId = cp['jwtId']
    expectedJwt = cp['expectedJwt']
    testAuthority = Authority('https://login.windows.net/naturalcauses.com/oauth2/token', False)
    testClientId = 'd6835713-b745-48d1-bb62-7a8248477d35'
    testCert = cp['cert']

    def _create_jwt(self, cert, thumbprint):
        ssjwt = SelfSignedJwt(cp['callContext'], self.testAuthority, self.testClientId)

        ssjwt._get_date_now = mock.MagicMock(return_value = self.testNowDate)
        ssjwt._get_new_jwt_id = mock.MagicMock(return_value = self.testJwtId)
        ssjwt._encode_jwt = mock.MagicMock(return_value = self.expectedJwt)

        jwt = ssjwt.create(cert, thumbprint)
        return jwt

    def _create_jwt_and_match_expected_err(self, testCert, thumbprint):
        with self.assertRaises(Exception):
            self._create_jwt(testCert, thumbprint)

    def _create_jwt_and_match_expected_jwt(self, cert, thumbprint):
        jwt = self._create_jwt(cert, thumbprint)
        self.assertTrue(jwt, 'No JWT generated')
        self.assertTrue(jwt == self.expectedJwt, 'Generated JWT does not match expected:{}'.format(jwt))

    def test_create_jwt_hash_colons(self):
        self._create_jwt_and_match_expected_jwt(self.testCert, cp['certHash'])

    def test_create_jwt_hash_spaces(self):
        thumbprint = cp['certHash'].replace(':', ' ')
        self._create_jwt_and_match_expected_jwt(self.testCert, thumbprint)

    def test_create_jwt_hash_straight_hex(self):
        thumbprint = cp['certHash'].replace(':', '')
        self._create_jwt_and_match_expected_jwt(self.testCert, thumbprint)

    def test_create_jwt_invalid_cert(self):
        self._create_jwt_and_match_expected_err('foobar', cp['certHash'])

    def test_create_jwt_invalid_thumbprint_1(self):
        self._create_jwt_and_match_expected_err(self.testCert, 'zzzz')

    def test_create_jwt_invalid_thumbprint_wrong_size(self):
        thumbprint = 'C1:5D:EA:86:56:AD:DF:67:BE:80:31:D8:5E:BD:DC:5A:D6:C4:36:E7:AA'
        self._create_jwt_and_match_expected_err(self.testCert, thumbprint)

    def test_create_jwt_invalid_thumbprint_invalid_char(self):
        thumbprint = 'C1:5D:EA:86:56:AD:DF:67:BE:80:31:D8:5E:BD:DC:5A:D6:C4:36:Ez'
        self._create_jwt_and_match_expected_err(self.testCert, thumbprint)

if __name__ == '__main__':
    unittest.main()
