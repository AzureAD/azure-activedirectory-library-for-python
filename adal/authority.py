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

import requests

try:
    from urllib.parse import quote
    from urllib.parse import urlparse

except ImportError:
    from urllib import quote
    from urlparse import urlparse

from .constants import AADConstants
from . import log
from . import util

class Authority(object):

    def __init__(self, authority_url, validate_authority=True):

        self._log = None
        self._call_context = None
        self._url = urlparse(authority_url)

        self._validate_authority_url()
        self._validated = not validate_authority

        self._host = None
        self._tenant = None
        self._parse_authority()

        self._authorization_endpoint = None
        self.token_endpoint = None

    @property
    def url(self):
        return self._url.geturl()

    def _validate_authority_url(self):

        if self._url.scheme != 'https':
            raise ValueError("The authority url must be an https endpoint.")

        if self._url.query:
            raise ValueError("The authority url must not have a query string.")

    def _parse_authority(self):
        self._host = self._url.hostname

        path_parts = self._url.path.split('/')
        try:
            self._tenant = path_parts[1]
        except IndexError:
            self._tenant = None

        if not self._tenant:
            raise ValueError("Could not determine tenant.")

    def _perform_static_instance_discovery(self):

        self._log.debug("Performing static instance discovery")

        try:
            AADConstants.WELL_KNOWN_AUTHORITY_HOSTS.index(self._url.hostname)
        except ValueError:
            return False

        self._log.debug("Authority validated via static instance discovery")
        return True

    def _create_authority_url(self):
        return "https://{0}/{1}{2}".format(self._url.hostname, self._tenant, AADConstants.AUTHORIZE_ENDPOINT_PATH)

    def _create_instance_discovery_endpoint_from_template(self, authority_host):

        discovery_endpoint = AADConstants.INSTANCE_DISCOVERY_ENDPOINT_TEMPLATE
        discovery_endpoint = discovery_endpoint.replace('{authorize_host}', authority_host)
        discovery_endpoint = discovery_endpoint.replace('{authorize_endpoint}', quote(self._create_authority_url(), safe='~()*!.\''))
        return urlparse(discovery_endpoint)

    def _perform_dynamic_instance_discovery(self, callback):

        try:
            discovery_endpoint = self._create_instance_discovery_endpoint_from_template(AADConstants.WORLD_WIDE_AUTHORITY)
            get_options = util.create_request_options(self)
            operation = "Instance Discovery"

            self._log.debug("Attempting instance discover at: {0}".format(discovery_endpoint.geturl()))

            try:
                resp = requests.get(discovery_endpoint.geturl(), headers=get_options['headers'])
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
                    discovery_resp = resp.json()
                    if discovery_resp.get('tenant_discovery_endpoint'):
                        callback(None, discovery_resp['tenant_discovery_endpoint'])
                    else:
                        callback(self._log.create_error('Failed to parse instance discovery response'), None)

            except Exception as exp:
                self._log.error("{0} request failed".format(operation), exp)
                callback(exp, None)

        except Exception as exp:
            self._log.error("{0} create_instance_discovery_endpoint_from_template failed".format(operation), exp)
            callback(exp, None)

    def _validate_via_instance_discovery(self, callback):

        if self._perform_static_instance_discovery():
            callback(None, None)
        else:
            self._perform_dynamic_instance_discovery(callback)

    def _get_oauth_endpoints(self, callback):

        if self.token_endpoint:
            callback(None)
            return

        else:
            self.token_endpoint = self._url.geturl() + AADConstants.TOKEN_ENDPOINT_PATH
            callback(None)
            return

    def validate(self, call_context, callback):

        self._log = log.Logger('Authority', call_context['log_context'])
        self._call_context = call_context

        if not self._validated:
            self._log.debug("Performing instance discovery: {0}".format(self._url.geturl()))

            def _callback(err, _):
                if err:
                    callback(err)
                else:
                    self._validated = True
                    self._get_oauth_endpoints(callback)
                    return

            self._validate_via_instance_discovery(_callback)

        else:
            self._log.debug("Instance discovery/validation has either already been completed or is turned off: {0}".format(self._url.geturl()))
            self._get_oauth_endpoints(callback)
            return
