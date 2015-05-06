import unittest
from tests import util
from adal.mex import Mex
import os
import httpretty

cp = util.parameters

class Test_Mex(unittest.TestCase):
    def test_happy_path_1(self):
        self._happyPathTest('microsoft.mex.xml', 'https://corp.sts.microsoft.com/adfs/services/trust/13/usernamemixed')

    def test_happy_path_2(self):
        self._happyPathTest('arupela.mex.xml', 'https://fs.arupela.com/adfs/services/trust/13/usernamemixed')

    def test_happy_path_3(self):
        self._happyPathTest('archan.us.mex.xml', 'https://arvmserver2012.archan.us/adfs/services/trust/13/usernamemixed')

    def test_malformed_xml_1(self):
        self._badMexDocTest('syntax.related.mex.xml')

    def test_malformed_xml_2(self):
        self._badMexDocTest('syntax.notrelated.mex.xml')

    def test_logically_invalid_no_ssl(self):
        self._badMexDocTest('address.insecure.xml')

    def test_logically_invalid_no_address(self):
        self._badMexDocTest('noaddress.xml')

    def test_logically_invalid_no_binding_port(self):
        self._badMexDocTest('nobinding.port.xml')

    def test_logically_invalid_no_binding_port(self):
        self._badMexDocTest('noname.binding.xml')

    def test_logically_invalid_no_soap_action(self):
        self._badMexDocTest('nosoapaction.xml')

    def test_logically_invalid_no_soap_transport(self):
        self._badMexDocTest('nosoaptransport.xml')

    def test_logically_invalid_no_uri_ref(self):
        self._badMexDocTest('nouri.ref.xml')

    def test_failed_request(self):
        httpretty.enable()
        httpretty.register_uri(httpretty.GET, uri = cp['adfsMex'], status = 500)

        mex = Mex(cp['callContext'], cp['adfsMex'])

        def verify(err, val):
            self.assertEqual(err.args[0], 'Mex Get request returned http error: 500 and server response: HTTPretty :)')

        mex.discover(verify)
        
        httpretty.disable()
        httpretty.reset()

    def _happyPathTest(self, file_name, expectedUrl):
        httpretty.enable()
        mexDocPath = os.path.join(os.getcwd(), 'tests', 'mex', file_name)
        mexDoc = open(mexDocPath).read()
        httpretty.register_uri(httpretty.GET, uri = cp['adfsMex'], body = mexDoc, status = 200)

        mex = Mex(cp['callContext'], cp['adfsMex'])

        def verify(err, val=None):
            self.assertFalse(err)
            self.assertEqual(mex.username_password_url, expectedUrl,
            'returned url did not match: ' + expectedUrl + ': ' + mex.username_password_url)

        mex.discover(verify)

        httpretty.disable()
        httpretty.reset()

    def _badMexDocTest(self, file_name):
        httpretty.enable()
        mexDocPath = os.path.join(os.getcwd(), 'tests', 'mex', file_name)
        mexDoc = open(mexDocPath).read()
        httpretty.register_uri(httpretty.GET, uri = cp['adfsMex'], body = mexDoc, status = 200)

        mex = Mex(cp['callContext'], cp['adfsMex'])

        def verify(err, val=None):
            self.assertTrue(err)

        mex.discover(verify)
        
        httpretty.disable()
        httpretty.reset()

if __name__ == '__main__':
    unittest.main()
