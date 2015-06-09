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
    testNowDate = datetime(2014, 12, 12, 17, 20, 46)
    testJwtId = '09841beb-a2c2-4777-a347-34ef055238a8'
    expectedJwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IndWM3FobGF0MzJlLWdESFlYcjNjV3RiRU51RSJ9.eyJhdWQiOiJodHRwczovL2xvZ2luLndpbmRvd3MubmV0L25hdHVyYWxjYXVzZXMuY29tL29hdXRoMi90b2tlbiIsImlzcyI6ImQ2ODM1NzEzLWI3NDUtNDhkMS1iYjYyLTdhODI0ODQ3N2QzNSIsInN1YiI6ImQ2ODM1NzEzLWI3NDUtNDhkMS1iYjYyLTdhODI0ODQ3N2QzNSIsIm5iZiI6MTQxODQzMzY0NiwiZXhwIjoxNDE4NDM0MjQ2LCJqdGkiOiIwOTg0MWJlYi1hMmMyLTQ3NzctYTM0Ny0zNGVmMDU1MjM4YTgifQ.AS3jyf9nUqBPeEFKccYA2NfSOSjDoWGW_QTj7Jqjbwpmp8jnQRkJ1Q9QrWLBIspesUVtctiKZQAl_BMochF_4yopY_JbYkPKEVvpbTojtwjKgTpVF175NUjXibUNCijx1BXRxEHJUbVJqzVSWBFtRCbXVBPg_ODqC0JJWutynnwMDec93gGOdWGi8AfRwj855zP41aDZGhQVFiOn3apzN4yfhOGoEeTbG4_6921Tkducz2jWpfVTxIS4yIOKCa97J6XInIlP1iW8XAsnGnTevanj8ubfCtYNRcCOrzq_qZstD6tSDqhQjJlTj5B0zlVvMjTT6oDTAOjzL4TuruENEg'
    testAuthority = Authority('https://login.windows.net/naturalcauses.com/oauth2/token', False)
    testClientId = 'd6835713-b745-48d1-bb62-7a8248477d35'
    testCert = util.get_self_signed_cert()

    def _create_jwt(self, cert, thumbprint):
        ssjwt = SelfSignedJwt(cp['callContext'], self.testAuthority, self.testClientId)

        ssjwt._get_date_now = mock.MagicMock(return_value = self.testNowDate)

        ssjwt._get_new_jwt_id = mock.MagicMock(return_value = self.testJwtId)

        jwt = ssjwt.create(cert, thumbprint)
        return jwt
    
    def _create_jwt_and_match_expected_err(self, testCert, thumbprint):
        with self.assertRaises(Exception):
            self._create_jwt(testCert, thumbprint)

    def _create_jwt_and_match_expected_jwt(self, cert, thumbprint):
        jwt = self._create_jwt(cert, thumbprint)
        self.assertTrue(jwt, 'No JWT generated')
        self.assertTrue(jwt == expectedJwt, 'Generated JWT does not match expected: {}'.format(jwt))

    def test_create_jwt_hash_colons(self):
        ''' 
        TODO: Test Failing as of 2015/06/09 and needs to be completed. 
        env34\lib\site-packages\Crypto\Random\OSRNG\nt.py", line 28, in <module>
        import winrandom
        ImportError: No module named 'winrandom'
        '''
        self._create_jwt_and_match_expected_jwt(self.testCert, cp['certHash'])

    def test_create_jwt_hash_spaces(self):
        ''' 
        TODO: Test Failing as of 2015/06/09 and needs to be completed. 
        env34\lib\site-packages\Crypto\Random\OSRNG\nt.py", line 28, in <module>
        import winrandom
        ImportError: No module named 'winrandom'
        '''
        thumbprint = cp['certHash'].replace(':', ' ')
        self._create_jwt_and_match_expected_jwt(self.testCert, thumbprint)

    def test_create_jwt_hash_straight_hex(self):
        ''' 
        TODO: Test Failing as of 2015/06/09 and needs to be completed. 
        env34\lib\site-packages\Crypto\Random\OSRNG\nt.py", line 28, in <module>
        import winrandom
        ImportError: No module named 'winrandom'
        '''
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
