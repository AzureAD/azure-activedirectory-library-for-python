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

from .constants import AADConstants

from . import constants
from . import log
from . import util

try:
    from urllib.parse import quote, unquote
    from urllib.parse import urlparse, urlsplit

except ImportError:
    from urllib import quote, unquote
    from urlparse import urlparse, urlsplit

class Authority(object):
    
    def __init__(self, authority_url, validate_authority):

        self._log = None
        self._call_context = None
        self._url = urlparse(authority_url)

        self._validate_authority_url()
        self._validated = not validate_authority

        self._host = None
        self._tenant = None
        self._parse_authority()

        self._authorization_endpoint = None
        self._token_endpoint = None

    @property
    def url(self):
        return self._url.geturl()

    @property
    def token_endpoint(self):
        return self._token_endpoint

    def _validate_authority_url(self):

        if self._url.scheme is not 'https':
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
            host_index = AADContants.WELL_KNOWN_AUTHORITY_HOSTS.index(self._url.hostname)
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

        except EXception as exp:
            self._log.error("{0} create_instance_discovery_endpoint_from_template failed".format(operation), exp)
            callback(exp, None)

    def _validate_via_instance_discovery(self, callback):

        if self._perform_static_instance_discovery():
            callback(None, None)
        else:
            self._perform_dynamic_instance_discovery(callback)

    def _get_oauth_endpoints(tenant_discovery_endpoint, callback):

        if self._token_endpoint:
            callback(None)
            return

        else:
            self._token_endpoint = self._url.geturl() + AADConstants.TOKEN_ENDPOINT_PATH
            callback(None)
            return

    def validate(call_context, callback):

        self._log = Logger('Authority', call_context['log_context'])
        self._call_context = call_context

        if not self._validated:
            self._log.debug("Performing instance discovery: {0}".format(self._url.geturl()))
            self._validate_via_instance_discovery()

            def _callback(err, tenant_dicovery_endpoint):
                if err:
                    callback(err)
                else:
                    self._validated = True
                    self._get_oauth_endpoints(tenant_dicovery_endpoint, callback)
                    return

            self._validate_via_instance_discovery(_callback)

        else:
            self._log.debug("Instance discovery/validation has either already been completed or is turned off: {0}".format(self._url.geturl()))
            self._get_oauth_endpoints(None, callback)
            return
