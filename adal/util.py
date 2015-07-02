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
import sys
import json
import inspect
import base64
import platform

from .constants import AdalIdParameters
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
