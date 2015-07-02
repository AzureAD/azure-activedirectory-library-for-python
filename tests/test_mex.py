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
import os
import unittest
import httpretty
from tests import util
from adal.mex import Mex

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

    @httpretty.activate
    def test_failed_request(self):
        httpretty.register_uri(httpretty.GET, uri = cp['adfsMex'], status = 500)

        mex = Mex(cp['callContext'], cp['adfsMex'])

        def verify(err, val):
            self.assertEqual(err.args[0], 'Mex Get request returned http error: 500 and server response: HTTPretty :)')

        mex.discover(verify)

    @httpretty.activate
    def _happyPathTest(self, file_name, expectedUrl):
        mexDocPath = os.path.join(os.getcwd(), 'tests', 'mex', file_name)
        mexDoc = open(mexDocPath).read()
        httpretty.register_uri(httpretty.GET, uri = cp['adfsMex'], body = mexDoc, status = 200)

        mex = Mex(cp['callContext'], cp['adfsMex'])

        def verify(err, val=None):
            self.assertFalse(err)
            self.assertEqual(mex.username_password_url, expectedUrl,
            'returned url did not match: ' + expectedUrl + ': ' + mex.username_password_url)

        mex.discover(verify)

    @httpretty.activate
    def _badMexDocTest(self, file_name):
        mexDocPath = os.path.join(os.getcwd(), 'tests', 'mex', file_name)
        mexDoc = open(mexDocPath).read()
        httpretty.register_uri(httpretty.GET, uri = cp['adfsMex'], body = mexDoc, status = 200)

        mex = Mex(cp['callContext'], cp['adfsMex'])

        def verify(err, val=None):
            self.assertTrue(err)

        mex.discover(verify)

if __name__ == '__main__':
    unittest.main()
