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
from adal.wstrust_request import WSTrustRequest
from adal.wstrust_response import WSTrustResponse
import httpretty
import os
import unittest.mock

TEST_CORRELATION_ID = 'test-correlation-id-123456789'
wstrustEndpoint = 'https://test.wstrust.endpoint/'
_call_context = { 'log_context' : {'correlation_id': TEST_CORRELATION_ID } }

class Test_wstrust_request(unittest.TestCase):

    #@httpretty.activate
    def test_happy_path(self):
        username = 'test_username'
        password = 'test_password'
        appliesTo = 'test_appliesTo'
        templateRST = open(os.getcwd() + r'\tests\wstrust\RST.xml', mode='r').read()
        rst = templateRST \
            .replace('%USERNAME%', username) \
            .replace('%PASSWORD%', password) \
            .replace('%APPLIES_TO%', appliesTo) \
            .replace('%WSTRUST_ENDPOINT%', wstrustEndpoint)

        #rstRequest = setupUpOutgoingRSTCompare(rst);
        request = WSTrustRequest(_call_context, wstrustEndpoint, appliesTo)

        # TODO: handle rstr should be mocked out to prevent handling here.
        # TODO: setupUpOutgoingRSTCompare.  Use this to get messageid, created, expires, etc comparisons.

        from httpretty import httpretty
        httpretty.enable()
        httpretty.register_uri(method=httpretty.POST, uri=wstrustEndpoint, status=200, body='')
        
        request._handle_rstr =unittest.mock.MagicMock()

        def callback():
            pass

        request.acquire_token(username, password, callback)

        

        httpretty.disable()
        httpretty.reset()

    def test_fail_to_parse_rstr(self):
        username = 'test_username'
        password = 'test_password'
        appliesTo = 'test_appliesTo'
        templateRST = open(os.getcwd() + r'\tests\wstrust\RST.xml', mode='r').read()
        rst = templateRST \
            .replace('%USERNAME%', username) \
            .replace('%PASSWORD%', password) \
            .replace('%APPLIES_TO%', appliesTo) \
            .replace('%WSTRUST_ENDPOINT%', wstrustEndpoint)


        from httpretty import httpretty
        httpretty.enable()
        httpretty.register_uri(method=httpretty.POST, uri=wstrustEndpoint, status=200, body='fake response body')

        def callback(err, token):
            self.assertEqual(err.args[0], 'Failed to parse RSTR in to DOM')
        
        request = WSTrustRequest(_call_context, wstrustEndpoint, appliesTo)
        request.acquire_token(username, password, callback)

        httpretty.disable()
        httpretty.reset()

if __name__ == '__main__':
    unittest.main()
