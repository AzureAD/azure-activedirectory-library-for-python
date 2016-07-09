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

try:
    from unittest import mock
except ImportError:
    import mock

from adal.wstrust_request import WSTrustRequest
from adal.wstrust_response import WSTrustResponse
from adal.constants import WSTrustVersion

TEST_CORRELATION_ID = 'test-correlation-id-123456789'
wstrustEndpoint = 'https://test.wstrust.endpoint/'
_call_context = { 'log_context' : {'correlation_id': TEST_CORRELATION_ID } }

class Test_wstrust_request(unittest.TestCase):

    @httpretty.activate
    def test_happy_path(self):
        username = 'test_username'
        password = 'test_password'
        appliesTo = 'test_appliesTo'
        wstrustFile = open(os.path.join(os.getcwd(), 'tests', 'wstrust', 'RST.xml'), mode='r')
        templateRST = wstrustFile.read()
        rst = templateRST \
            .replace('%USERNAME%', username) \
            .replace('%PASSWORD%', password) \
            .replace('%APPLIES_TO%', appliesTo) \
            .replace('%WSTRUST_ENDPOINT%', wstrustEndpoint)

        #rstRequest = setupUpOutgoingRSTCompare(rst)
        request = WSTrustRequest(_call_context, wstrustEndpoint, appliesTo, WSTrustVersion.WSTRUST13)

        # TODO: handle rstr should be mocked out to prevent handling here.
        # TODO: setupUpOutgoingRSTCompare.  Use this to get messageid, created, expires, etc comparisons.

        httpretty.register_uri(method=httpretty.POST, uri=wstrustEndpoint, status=200, body='')

        request._handle_rstr =mock.MagicMock()

        request.acquire_token(username, password)
        wstrustFile.close()

    @httpretty.activate
    def test_fail_to_parse_rstr(self):
        username = 'test_username'
        password = 'test_password'
        appliesTo = 'test_appliesTo'
        templateFile = open(os.path.join(os.getcwd(), 'tests', 'wstrust', 'RST.xml'), mode='r')
        templateRST = templateFile.read()
        templateFile.close()
        rst = templateRST \
            .replace('%USERNAME%', username) \
            .replace('%PASSWORD%', password) \
            .replace('%APPLIES_TO%', appliesTo) \
            .replace('%WSTRUST_ENDPOINT%', wstrustEndpoint)

        httpretty.register_uri(method=httpretty.POST, uri=wstrustEndpoint, status=200, body='fake response body')

        request = WSTrustRequest(_call_context, wstrustEndpoint, appliesTo, WSTrustVersion.WSTRUST13)
        with self.assertRaises(Exception):
            request.acquire_token(username, password)


if __name__ == '__main__':
    unittest.main()
