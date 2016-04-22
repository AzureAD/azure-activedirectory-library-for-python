﻿#------------------------------------------------------------------------------
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

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET

from . import xmlutil
from . import log
from .adal_error import AdalError

class WSTrustResponse(object):

    def __init__(self, call_context, response):

        self._log = log.Logger("WSTrustResponse", call_context['log_context'])
        self._call_context = call_context
        self._response = response
        self._dom = None
        self._parents = None
        self.error_code = None
        self.fault_message = None
        self.token_type = None
        self.token = None

        self._log.debug("RSTR Response: %s", self._response)

    # Sample error message
    #<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    #   <s:Header>
    #    <a:Action s:mustUnderstand="1">http://www.w3.org/2005/08/addressing/soap/fault</a:Action>
    #  - <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    #      <u:Timestamp u:Id="_0">
    #      <u:Created>2013-07-30T00:32:21.989Z</u:Created>
    #      <u:Expires>2013-07-30T00:37:21.989Z</u:Expires>
    #      </u:Timestamp>
    #    </o:Security>
    #    </s:Header>
    #  <s:Body>
    #    <s:Fault>
    #      <s:Code>
    #        <s:Value>s:Sender</s:Value>
    #        <s:Subcode>
    #        <s:Value xmlns:a="http://docs.oasis-open.org/ws-sx/ws-trust/200512">a:RequestFailed</s:Value>
    #        </s:Subcode>
    #      </s:Code>
    #      <s:Reason>
    #      <s:Text xml:lang="en-US">MSIS3127: The specified request failed.</s:Text>
    #      </s:Reason>
    #    </s:Fault>
    # </s:Body>
    #</s:Envelope>

    def _parse_error(self):

        error_found = False

        fault_node = xmlutil.xpath_find(self._dom, 's:Body/s:Fault/s:Reason/s:Text')
        if fault_node:
            self.fault_message = fault_node[0].text

            if self.fault_message:
                error_found = True

        # Subcode has minoccurs=0 and maxoccurs=1(default) according to the http://www.w3.org/2003/05/soap-envelope
        # Subcode may have another subcode as well. This is only targetting at top level subcode.
        # Subcode value may have different messages not always uses http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd.
        # text inside the value is not possible to select without prefix, so substring is necessary
        subnode = xmlutil.xpath_find(self._dom, 's:Body/s:Fault/s:Code/s:Subcode/s:Value')
        if len(subnode) > 1:
            raise AdalError("Found too many fault code values: {}".format(len(subnode)))

        if subnode:
            error_code = subnode[0].text
            self.error_code = error_code.split(':')[1]

        return error_found

    def _parse_token(self):
        token_type_nodes = xmlutil.xpath_find(self._dom, 's:Body/wst:RequestSecurityTokenResponseCollection/wst:RequestSecurityTokenResponse/wst:TokenType')
        if not token_type_nodes:
            raise AdalError("No TokenType nodes found in RSTR")

        for node in token_type_nodes:
            if self.token:
                self._log.warn("Found more than one returned token. Using the first.")
                break

            token_type = xmlutil.find_element_text(node)
            if not token_type:
                self._log.warn("Could not find token type in RSTR token.")

            requested_token_node = xmlutil.xpath_find(self._parents[node], 'wst:RequestedSecurityToken')
            if len(requested_token_node) > 1:
                raise AdalError("Found too many RequestedSecurityToken nodes for token type: {}".format(token_type))

            if not requested_token_node:
                self._log.warn(
                    "Unable to find RequestsSecurityToken element associated with TokenType element: %s", 
                    token_type)
                continue

            # Adjust namespaces (without this they are autogenerated) so this is understood
            # by the receiver.  Then make a string repr of the element tree node.
            ET.register_namespace('saml', 'urn:oasis:names:tc:SAML:1.0:assertion')
            ET.register_namespace('ds', 'http://www.w3.org/2000/09/xmldsig#')

            token = ET.tostring(requested_token_node[0][0])

            if token is None:
                self._log.warn(
                    "Unable to find token associated with TokenType element: %s",
                    token_type)
                continue

            self.token = token
            self.token_type = token_type

            self._log.info("Found token of type: %s", self.token_type)

        if self.token is None:
            raise AdalError("Unable to find any tokens in RSTR.")

    def parse(self):
        if not self._response:
            raise AdalError("Received empty RSTR response body.")

        try:

            try:
                self._dom = ET.fromstring(self._response)
            except Exception as exp:
                raise AdalError('Failed to parse RSTR in to DOM', exp)

            self._parents = {c:p for p in self._dom.iter() for c in p}
            error_found = self._parse_error()
            if error_found:
                str_error_code = self.error_code or 'NONE'
                str_fault_message = self.fault_message or 'NONE'
                error_template = 'Server returned error in RSTR - ErrorCode: {} : FaultMessage: {}'
                raise AdalError(error_template.format(str_error_code, str_fault_message))
            self._parse_token()
        finally:
            self._log.info("Failed to parse RSTR in to DOM")
            self._dom = None
            self._parents = None

