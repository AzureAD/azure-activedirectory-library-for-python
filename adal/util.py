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

import json
import inspect
import os
import sys
import base64

from .constants import AdalIdParameters
import platform

import adal

try:
    from urllib.parse import quote, unquote
    from urllib.parse import urlparse, urlsplit

except ImportError:
    from urllib import quote, unquote
    from urlparse import urlparse, urlsplit

def is_http_success(status_code):
    return status_code >= 200 and status_code < 300

def add_default_request_headers(self, options):
    if not options.get('headers'):
        options['headers'] = {}

    headers = options['headers']
    if not headers.get('Accept-Charset'):
        headers['Accept-Charset'] = 'utf-8'

    headers['client-request-id'] = self._call_context['log_context']['correlation_id']
    headers['return-client-request-id'] = 'true'

    headers[AdalIdParameters.SKU] = AdalIdParameters.PYTHON_SKU
    headers[AdalIdParameters.VERSION] = adal.__version__
    headers[AdalIdParameters.OS] = sys.platform
    headers[AdalIdParameters.CPU] = 'x64' if platform.architecture()[0] == '64bit' else 'x86'

def create_request_options(self, *options):

    merged_options = {}

    if options:
        for i in options:
            merged_options.update(i)

    if self._call_context.get('options') and self._call_context['options'].get('http'):
        merged_options.update(self._call_context['options']['http'])

    add_default_request_headers(self, merged_options)
    return merged_options


def log_return_correlation_id(log, operation_message, response):
    if response and response.headers and response.headers.get('client-request-id'):
        log.info("{0} Server returned this correlation_id: {1}".format(operation_message, response.headers['client-request-id']))

#def create_request_handler(operation_message, log, error_callback, success_callback):

#    def req_handler(err, response, body):
#        log_return_correlation_id(log, operation_message, response)
#        if err:
#            log.error("{0} request failed with {1}".format(operation_message, err))
#            error_callback(err)
#            return

#        if not is_http_success(response.status_code):
#            return_error_string = "{0} request returned http error: {1}".format(operation_message, response.status_code)
#            error_response = ""
#            if body:
#                return_error_string += " and server response: {0}".format(body)
#                try:
#                    error_response = json.loads(body)
#                except:
#                    pass

#            error_callback(log.create_error(return_error_string), error_response)
#            return

#        success_callback(response, body)

#    return req_handler

def copy_url(url_source):
    if hasattr(url_source, 'geturl'):
        return urlparse(url_source.geturl())
    else:
        return urlparse(url_source)
