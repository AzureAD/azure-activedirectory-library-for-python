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
import os
import six

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from adal.constants import XmlNamespaces, Errors, WSTrustVersion
from adal.wstrust_response import WSTrustResponse
from adal.wstrust_response import findall_content

_namespaces = XmlNamespaces.namespaces
_call_context = {'log_context' : {'correlation-id':'test-corr-id'}}

class Test_wstrustresponse(unittest.TestCase):
    def test_parse_error_happy_path(self):
        errorResponse = '''
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
              <s:Header>
               <a:Action s:mustUnderstand="1">http://www.w3.org/2005/08/addressing/soap/fault</a:Action>
               <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                 <u:Timestamp u:Id="_0">
                 <u:Created>2013-07-30T00:32:21.989Z</u:Created>
                 <u:Expires>2013-07-30T00:37:21.989Z</u:Expires>
                 </u:Timestamp>
               </o:Security>
               </s:Header>
             <s:Body>
               <s:Fault>
                 <s:Code>
                   <s:Value>s:Sender</s:Value>
                   <s:Subcode>
                   <s:Value xmlns:a="http://docs.oasis-open.org/ws-sx/ws-trust/200512">a:RequestFailed</s:Value>
                   </s:Subcode>
                 </s:Code>
                 <s:Reason>
                 <s:Text xml:lang="en-US">MSIS3127: The specified request failed.</s:Text>
                 </s:Reason>
               </s:Fault>
            </s:Body>
            </s:Envelope>'''

        wstrustResponse = WSTrustResponse(_call_context, errorResponse, WSTrustVersion.WSTRUST13)

        exception_text = "Server returned error in RSTR - ErrorCode: RequestFailed : FaultMessage: MSIS3127: The specified request failed"
        with six.assertRaisesRegex(self, Exception, exception_text) as cm:
            wstrustResponse.parse()

    def test_token_parsing_happy_path(self):
        wstrustFile = open(os.path.join(os.getcwd(), 'tests', 'wstrust', 'RSTR.xml'))
        wstrustResponse = WSTrustResponse(_call_context, wstrustFile.read(), WSTrustVersion.WSTRUST13)
        wstrustResponse.parse()
        wstrustFile.close()

        self.assertEqual(wstrustResponse.token_type, 'urn:oasis:names:tc:SAML:1.0:assertion', 'TokenType did not match expected value: ' + wstrustResponse.token_type)

        attribute_values = ET.fromstring(wstrustResponse.token).findall('saml:AttributeStatement/saml:Attribute/saml:AttributeValue', _namespaces)
        self.assertEqual(2, len(attribute_values))
        self.assertEqual('1TIu064jGEmmf+hnI+F0Jg==', attribute_values[1].text)

    def test_rstr_none(self):
        with six.assertRaisesRegex(self, Exception, 'Received empty RSTR response body.') as cm:
            wstrustResponse = WSTrustResponse(_call_context, None, WSTrustVersion.WSTRUST13)
            wstrustResponse.parse()

    def test_rstr_empty_string(self):
        with six.assertRaisesRegex(self, Exception, 'Received empty RSTR response body.') as cm:
            wstrustResponse = WSTrustResponse(_call_context, '', WSTrustVersion.WSTRUST13)
            wstrustResponse.parse()

    def test_rstr_unparseable_xml(self):
        with six.assertRaisesRegex(self, Exception, 'Failed to parse RSTR in to DOM'):
            wstrustResponse = WSTrustResponse(_call_context, '<This is not parseable as an RSTR', WSTrustVersion.WSTRUST13)
            wstrustResponse.parse()

    def test_findall_content_with_comparison(self):
        content = """
            <saml:Assertion xmlns:saml="SAML:assertion">
                <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                foo
                </ds:Signature>
            </saml:Assertion>"""
        sample = ('<ns0:Wrapper xmlns:ns0="namespace0">'
            + content
            + '</ns0:Wrapper>')

        # Demonstrating how XML-based parser won't give you the raw content as-is
        element = ET.fromstring(sample).findall('{SAML:assertion}Assertion')[0]
        assertion_via_xml_parser = ET.tostring(element)
        self.assertNotEqual(content, assertion_via_xml_parser)
        self.assertNotIn(b"<ds:Signature>", assertion_via_xml_parser)

        # The findall_content() helper, based on Regex, will return content as-is.
        self.assertEqual([content], findall_content(sample, "Wrapper"))

    def test_findall_content_for_real(self):
        with open(os.path.join(os.getcwd(), 'tests', 'wstrust', 'RSTR.xml')) as f:
            rstr = f.read()
        wstrustResponse = WSTrustResponse(_call_context, rstr, WSTrustVersion.WSTRUST13)
        wstrustResponse.parse()
        self.assertIn("<X509Data>", rstr)
        self.assertIn(b"<X509Data>", wstrustResponse.token)  # It is in bytes

if __name__ == '__main__':
    unittest.main()
