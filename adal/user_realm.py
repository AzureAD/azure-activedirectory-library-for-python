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
import json
import requests

try:
    from urllib.parse import quote, urlencode
    from urllib.parse import urlunparse
except ImportError:
    from urllib import quote, urlencode
    from urlparse import urlunparse

from . import constants
from . import log
from . import util

USER_REALM_PATH_TEMPLATE = 'common/UserRealm/<user>'

ACCOUNT_TYPE = constants.UserRealm.account_type
FEDERATION_PROTOCOL_TYPE = constants.UserRealm.federation_protocol_type


class UserRealm(object):

    def __init__(self, call_context, user_principle, authority_url):

        self._log = log.Logger("UserRealm", call_context['log_context'])
        self._call_context = call_context
        self.api_version = '1.0'
        self.federation_protocol = None
        self.account_type = None
        self.federation_metadata_url = None
        self.federation_active_auth_url = None
        self._user_principle = user_principle
        self._authority_url = authority_url

    def _get_user_realm_url(self):

        user_realm_url = list(util.copy_url(self._authority_url))
        url_encoded_user = quote(self._user_principle, safe='~()*!.\'')
        user_realm_url[2] = '/' + USER_REALM_PATH_TEMPLATE.replace('<user>', url_encoded_user)

        user_realm_query = {'api-version':self.api_version}
        user_realm_url[4] = urlencode(user_realm_query)
        user_realm_url = util.copy_url(urlunparse(user_realm_url))

        return user_realm_url

    def _validate_constant_value(self, constants, value, case_sensitive=False):

        if not value:
            return False

        if not case_sensitive:
            value = value.lower()

        return value if value in constants.values() else False

    def _validate_account_type(self, type):
        return self._validate_constant_value(ACCOUNT_TYPE, type)

    def _validate_federation_protocol(self, protocol):
        return self._validate_constant_value(FEDERATION_PROTOCOL_TYPE, protocol)

    def _log_parsed_response(self):

        self._log.debug('UserRealm response:')
        self._log.debug(' AccountType:             {0}'.format(self.account_type))
        self._log.debug(' FederationProtocol:      {0}'.format(self.federation_protocol))
        self._log.debug(' FederationMetatdataUrl:  {0}'.format(self.federation_metadata_url))
        self._log.debug(' FederationActiveAuthUrl: {0}'.format(self.federation_active_auth_url))

    def _parse_discovery_response(self, body, callback):

        self._log.debug("Discovery response:\n{0}".format(body))

        response = None
        try:
            response = json.loads(body)
        except Exception as exp:
            callback(self._log.create_error('Parsing realm discovery response JSON failed: {0}'.format(body)))
            return

        account_type = self._validate_account_type(response['account_type'])
        if not account_type:
            callback(self._log.create_error('Cannot parse account_type: {0}'.format(account_type)))
            return
        self.account_type = account_type

        if self.account_type == ACCOUNT_TYPE['Federated']:
            protocol = self._validate_federation_protocol(response['federation_protocol'])

            if not protocol:
                callback(self._log.create_error('Cannot parse federation protocol: {0}'.format(protocol)))
                return

            self.federation_protocol = protocol
            self.federation_metadata_url = response['federation_metadata_url']
            self.federation_active_auth_url = response['federation_active_auth_url']

        self._log_parsed_response()
        callback(None)

    def discover(self, callback):

        options = util.create_request_options(self, {'headers': {'Accept':'application/json'}})
        user_realm_url = self._get_user_realm_url()
        self._log.debug("Performing user realm discovery at: {0}".format(user_realm_url.geturl()))

        operation = 'User Realm Discovery'
        try:
            resp = requests.get(user_realm_url.geturl(), headers=options['headers'])
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
                self._parse_discovery_response(resp.text, callback)

        except Exception as exp:
            self._log.error("{0} request failed".format(operation), exp)
            callback(exp)
            return
