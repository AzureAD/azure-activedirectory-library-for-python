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

import requests

from . import log
from . import util
from . import xmlutil

import random

try:
    from urllib.parse import quote, unquote
    from urllib.parse import urlparse, urlsplit

except ImportError:
    from urllib import quote, unquote
    from urlparse import urlparse, urlsplit

from xml.etree import ElementTree
from xml.dom.minidom import parseString
from .constants import XmlNamespaces

TRANSPORT_BINDING_XPATH = 'wsp:ExactlyOne/wsp:All/sp:TransportBinding'
TRANSPORT_BINDING_2005_XPATH = 'wsp:ExactlyOne/wsp:All/sp2005:TransportBinding'

SOAP_ACTION_XPATH = 'wsdl:operation/soap12:operation'
RST_SOAP_ACTION = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue'
SOAP_TRANSPORT_XPATH = 'soap12:binding'
SOAP_HTTP_TRANSPORT_VALUE = 'http://schemas.xmlsoap.org/soap/http'

PORT_XPATH = 'wsdl:service/wsdl:port'
ADDRESS_XPATH = 'wsa10:EndpointReference/wsa10:Address'


class Mex(object):

    def __init__(self, call_context, url):

        self._log = log.Logger("MEX", call_context.get('log_context'))
        self._call_context = call_context
        self._url = url
        self._dom = None
        self._parents = None
        self._mex_doc = None
        self._user_pass_url = None
        self._log.debug("Mex created with url: {0}".format(self._url))

    @property
    def username_password_url(self):
        return self._user_pass_url

    def discover(self, callback):

        self._log.debug("Retrieving mex at: {0}".format(self._url))
        options = util.create_request_options(self, {'headers': {'Content-Type': 'application/soap+xml'}})

        try:
            operation = "Mex Get"
            resp = requests.get(self._url, headers=options['headers'])
            util.log_return_correlation_id(self._log, operation, resp)

            if not util.is_http_success(resp.status_code):
                return_error_string = "{0} request returned http error: {1}".format(operation, resp.status_code)
                error_response = ""
                if resp.text:
                    return_error_string += " and server response: {0}".format(resp.text)
                    try:
                        error_response = resp.json()
                    except:
                        pass

                callback(self._log.create_error(return_error_string), error_response)
                return

            else:
                try:
                    self._mex_doc = resp.text
                    #options = {'errorHandler':self._log.error}
                    self._dom = ElementTree.fromstring(self._mex_doc)
                    self._parents = {c:p for p in self._dom.iter() for c in p}
                    self._parse(callback)

                except Exception as err:
                    self._log.error('Failed to parse mex response in to DOM', err)
                    callback(err, None)
                    return
                return
            return

        except Exception as err:
            self._log.error("{0} request failed".format(operation), err)
            callback(err, None)

    def _check_policy(self, policy_node):

        policy_id = None
        id = policy_node.attrib["{{{}}}Id".format(XmlNamespaces.namespaces['wsu'])]
        transport_binding_nodes = xmlutil.xpath_find(policy_node, TRANSPORT_BINDING_XPATH)
        if not transport_binding_nodes:
            transport_binding_nodes = xmlutil.xpath_find(policy_node, TRANSPORT_BINDING_2005_XPATH)
        else:
            if id:
                policy_id = id

        if policy_id:
            self._log.debug("Found matching policy id: {0}".format(policy_id))
        else:
            if not id:
                id = "<no id>"
            self._log.debug("Potential policy did not match required transport binding: {0}".format(id))
        return policy_id

    def _select_username_password_polices(self):

        policies = {}
        xpath = 'wsp:Policy/wsp:ExactlyOne/wsp:All/sp:SignedEncryptedSupportingTokens/wsp:Policy/sp:UsernameToken/wsp:Policy/sp:WssUsernameToken10'
        username_token_nodes = xmlutil.xpath_find(self._dom, xpath)
        if not username_token_nodes:
            self._log.warn("No username token policy nodes found.")
            return

        for node in username_token_nodes:
            policy_node = self._parents[self._parents[self._parents[self._parents[self._parents[self._parents[self._parents[node]]]]]]]
            id = self._check_policy(policy_node)
            if id:
                id_ref = '#' + id
                policies[id_ref] = {id:id_ref}

        return policies if policies else None

    def _check_soap_action_and_transport(self, binding_node):

        soap_action = ""
        soap_transport = ""
        name = binding_node.get('name')

        soap_transport_attributes = []
        soap_action_attributes = xmlutil.xpath_find(binding_node, SOAP_ACTION_XPATH)[0].attrib['soapAction']

        if soap_action_attributes:
            soap_action = soap_action_attributes
            soap_transport_attributes = xmlutil.xpath_find(binding_node, SOAP_TRANSPORT_XPATH)[0].attrib['transport']

        if soap_transport_attributes:
            soap_transport = soap_transport_attributes

        found = soap_action == RST_SOAP_ACTION and soap_transport == SOAP_HTTP_TRANSPORT_VALUE
        if found:
            self._log.debug("Found binding matching Action and Transport: {0}".format(name))
        else:
            self._log.debug("Binding node did not match soap Action or Transport: {0}".format(name))

        return found

    def _get_matching_bindings(self, policies):

        bindings = {}
        binding_policy_ref_nodes = xmlutil.xpath_find(self._dom, 'wsdl:binding/wsp:PolicyReference')

        for node in binding_policy_ref_nodes:
            uri = node.get('URI')
            policy = policies.get(uri)
            if policy:
                binding_node = self._parents[node]
                binding_name = binding_node.get('name')

                if self._check_soap_action_and_transport(binding_node):
                    bindings[binding_name] = uri

        return bindings if bindings else None

    def _url_is_secure(self, endpoint_url):

        parsed = urlparse(endpoint_url)
        return parsed.scheme == 'https'

    def _get_ports_for_policy_bindings(self, bindings, policies):

        port_nodes = xmlutil.xpath_find(self._dom, PORT_XPATH)
        if not port_nodes:
            self._log.warn("No ports found")

        for node in port_nodes:
            binding_id = node.get('binding')
            binding_id = binding_id.split(':')[-1]

            binding_policy = policies.get(bindings.get(binding_id))
            if binding_policy:
                if not binding_policy.get('url', None):
                    address_node = node.find(ADDRESS_XPATH, XmlNamespaces.namespaces)
                    if address_node is None:
                        raise self._log.create_error("No address nodes on port")

                    address = xmlutil.find_element_text(address_node)
                    if self._url_is_secure(address):
                        binding_policy['url'] = address
                    else:
                        self._log.warn("Skipping insecure endpoint: {0}".format(address))

    def _select_single_matching_policy(self, policies):

        matching_policies = [p for p in policies.values() if p.get('url')]
        if not matching_policies:
            self._log.warn("No policies found with a url.")
            return

        random.shuffle(matching_policies)
        self._user_pass_url = matching_policies[0]['url']

    def _parse(self, callback):

        policies = self._select_username_password_polices()
        if not policies:
            callback(self._log.create_error("No matching policies."))
            return

        bindings = self._get_matching_bindings(policies)
        if not bindings:
            callback(self._log.create_error("No matching bindings."))
            return

        self._get_ports_for_policy_bindings(bindings, policies)
        self._select_single_matching_policy(policies)

        if self._url:
            callback(None)
        else:
            callback(self._log.create_error("No ws-trust endpoints match requirements."))
