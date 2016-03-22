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

from datetime import datetime, timedelta
import math
import uuid
import requests
import re
import json
import time

try:
    from urllib.parse import urlencode
    from urllib.parse import urlparse
except ImportError:
    from urllib import urlencode
    from urlparse import urlparse

from . import log
from . import util
from .constants import OAuth2, TokenResponseFields, IdTokenFields
from .token_request_error import TokenRequestError

TOKEN_RESPONSE_MAP = {
    OAuth2.ResponseParameters.TOKEN_TYPE : TokenResponseFields.TOKEN_TYPE,
    OAuth2.ResponseParameters.ACCESS_TOKEN : TokenResponseFields.ACCESS_TOKEN,
    OAuth2.ResponseParameters.REFRESH_TOKEN : TokenResponseFields.REFRESH_TOKEN,
    OAuth2.ResponseParameters.CREATED_ON : TokenResponseFields.CREATED_ON,
    OAuth2.ResponseParameters.EXPIRES_ON : TokenResponseFields.EXPIRES_ON,
    OAuth2.ResponseParameters.EXPIRES_IN : TokenResponseFields.EXPIRES_IN,
    OAuth2.ResponseParameters.RESOURCE : TokenResponseFields.RESOURCE,
    OAuth2.ResponseParameters.ERROR : TokenResponseFields.ERROR,
    OAuth2.ResponseParameters.ERROR_DESCRIPTION : TokenResponseFields.ERROR_DESCRIPTION,
}

#DEVICE_CODE_RESPONSE_MAP = {
#    OAuth2.DeviceCodeResponseParameters.DEVICE_CODE: UserCodeResponseFields.DEVICE_CODE,
#    OAuth2.DeviceCodeResponseParameters.: UserCodeResponseFields.,
#    OAuth2.DeviceCodeResponseParameters.: UserCodeResponseFields.,
#    OAuth2.DeviceCodeResponseParameters.: UserCodeResponseFields.,
#    OAuth2.DeviceCodeResponseParameters.: UserCodeResponseFields.,
#    OAuth2.DeviceCodeResponseParameters.: UserCodeResponseFields.,
#    OAuth2.DeviceCodeResponseParameters.: UserCodeResponseFields.,
#    OAuth2.DeviceCodeResponseParameters.: UserCodeResponseFields.,
#}

def map_fields(in_obj, map_to):
    return dict((map_to[k], v) for k, v in in_obj.items() if k in map_to)


class OAuth2Client(object):

    def __init__(self, call_context, authority):
        self._token_endpoint = authority.token_endpoint
        self._device_code_endpoint = authority.device_code_endpoint
        self._log = log.Logger("OAuth2Client", call_context['log_context'])
        self._call_context = call_context
        self._cancel_polling_request = False

    def _create_token_url(self):
        parameters = {}
        parameters[OAuth2.Parameters.AAD_API_VERSION] = '1.0'

        return urlparse('{}?{}'.format(self._token_endpoint, urlencode(parameters)))

    def _create_device_code_url(self):
        parameters = {}
        parameters[OAuth2.Parameters.AAD_API_VERSION] = '1.0'
        return urlparse('{}?{}'.format(self._device_code_endpoint, urlencode(parameters)))

    def _parse_optional_ints(self, obj, keys):
        for key in keys:
            try:
                obj[key] = int(obj[key])
            except ValueError:
                raise self._log.create_error("{0} could not be parsed as an int".format(key))
            except KeyError:
                # if the key isn't present we can just continue
                pass
    
    @classmethod
    def _crack_jwt(cls, jwt_token):

        id_token_parts_reg = "^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$"
        matches = re.search(id_token_parts_reg, jwt_token)
        if not matches or len(matches.groups()) < 3:
            raise ValueError('The token was not parsable.')

        cracked_token = {
            'header': matches.group(1),
            'JWSPayload': matches.group(2),
            'JWSSig': matches.group(3)
            }

        return cracked_token

    def _get_user_id(self, id_token):

        user_id = None
        is_displayable = False

        if id_token.get('upn'):
            user_id = id_token['upn']
            is_displayable = True
        elif id_token.get('email'):
            user_id = id_token['email']
            is_displayable = True
        elif id_token.get('subject'):
            user_id = id_token['subject']

        if not user_id:
            user_id = str(uuid.uuid4())

        user_id_vals = {}
        user_id_vals[IdTokenFields.USER_ID] = user_id

        if is_displayable:
            user_id_vals[IdTokenFields.IS_USER_ID_DISPLAYABLE] = True

        return user_id_vals

    def _extract_token_values(self, id_token):
        extracted_values = {}
        extracted_values = map_fields(id_token, OAuth2.IdTokenMap)
        extracted_values.update(self._get_user_id(id_token))
        return extracted_values

    def _parse_id_token(self, encoded_token):

        cracked_token = self._crack_jwt(encoded_token)
        if not cracked_token:
            return

        id_token = None
        try:
            b64_id_token = cracked_token['JWSPayload']
            b64_decoded = util.base64_urlsafe_decode(b64_id_token)
            if not b64_decoded:
                self._log.warn('The returned id_token could not be base64 url safe decoded.')
                return

            id_token = json.loads(b64_decoded.decode())

        except Exception as exp:
            self._log.warn("The returned id_token could not be decoded: {0}".format(exp))
            return

        return self._extract_token_values(id_token)

    def _validate_token_response(self, body):

        wire_response = None
        token_response = {}

        try:
            wire_response = json.loads(body)
        except Exception:
            raise ValueError('The token response returned from the server is unparseable as JSON')

        int_keys = [
            OAuth2.ResponseParameters.EXPIRES_ON,
            OAuth2.ResponseParameters.EXPIRES_IN,
            OAuth2.ResponseParameters.CREATED_ON
          ]

        self._parse_optional_ints(wire_response, int_keys)

        expires_in = wire_response.get(OAuth2.ResponseParameters.EXPIRES_IN)
        if expires_in:
            now = datetime.now()
            soon = timedelta(seconds=expires_in)
            wire_response[OAuth2.ResponseParameters.EXPIRES_ON] = str(now + soon)

        created_on = wire_response.get(OAuth2.ResponseParameters.CREATED_ON)
        if created_on:
            temp_date = datetime.fromtimestamp(created_on)
            wire_response[OAuth2.ResponseParameters.CREATED_ON] = str(temp_date)

        if not wire_response.get(OAuth2.ResponseParameters.TOKEN_TYPE):
            raise self._log.create_error('wire_response is missing token_type')

        if not wire_response.get(OAuth2.ResponseParameters.ACCESS_TOKEN):
            raise self._log.create_error('wire_response is missing access_token')

        token_response = map_fields(wire_response, TOKEN_RESPONSE_MAP)

        if wire_response.get(OAuth2.ResponseParameters.ID_TOKEN):
            id_token = self._parse_id_token(wire_response[OAuth2.ResponseParameters.ID_TOKEN])
            if id_token:
                token_response.update(id_token)

        return token_response

    def _validate_device_code_response(self, body):

        wire_response = None
        #device_code_response = {}

        try:
            wire_response = json.loads(body)
        except Exception:
            raise ValueError('The device code response returned from the server is unparseable as JSON')

        int_keys = [
            OAuth2.DeviceCodeResponseParameters.EXPIRES_IN,
            OAuth2.DeviceCodeResponseParameters.INTERVAL
          ]

        self._parse_optional_ints(wire_response, int_keys)

        if not wire_response.get(OAuth2.DeviceCodeResponseParameters.EXPIRES_IN):
            raise self._log.create_error('wire_response is missing expires_in')

        if not wire_response.get(OAuth2.DeviceCodeResponseParameters.DEVICE_CODE):
            raise self._log.create_error('wire_response is missing device_code')

        if not wire_response.get(OAuth2.DeviceCodeResponseParameters.USER_CODE):
            raise self._log.create_error('wire_response is missing user_code')

        #we skip the field naming mapping
        return wire_response

    def _handle_get_token_response(self, body):

        token_response = None
        try:
            token_response = self._validate_token_response(body)
        except Exception as exp:
            self._log.error("Error validating get token response", exp)
            raise exp

        return token_response

    def _handle_get_device_code_response(self, body):

        device_code_response = None
        try:
            device_code_response = self._validate_device_code_response(body)
        except Exception as exp:
            self._log.error('Error validating get user vcode response', exp)
            raise exp

        return device_code_response

    def get_token(self, oauth_parameters):

        token_url = self._create_token_url()
        url_encoded_token_request = urlencode(oauth_parameters)

        post_options = util.create_request_options(self, {'headers' : {'content-type': 'application/x-www-form-urlencoded'}})
        operation = "Get Token"

        try:
            resp = requests.post(token_url.geturl(), data=url_encoded_token_request, headers=post_options['headers'])
            util.log_return_correlation_id(self._log, operation, resp)

            if util.is_http_success(resp.status_code):
                token = self._handle_get_token_response(resp.text)
                return token
            else:
                return_error_string = "{0} request returned http error: {1}".format(operation, resp.status_code)
                error_response = ""
                if resp.text:
                    return_error_string += " and server response: {0}".format(resp.text)
                    try:
                        error_response = resp.json()
                    except:
                        pass

                raise TokenRequestError(self._log.create_error(return_error_string), error_response)

        except Exception as exp:
            self._log.error("{0} request failed".format(operation), exp)
            raise exp

    def get_user_code_info(self, oauth_parameters):
        device_code_url = self._create_device_code_url()
        url_encoded_code_request = urlencode(oauth_parameters)

        post_options = util.create_request_options(self, {'headers' : {'content-type': 'application/x-www-form-urlencoded'}})
        operation = "Get Device Code"
        
        try:
            resp = requests.post(device_code_url.geturl(), data=url_encoded_code_request, headers=post_options['headers'])
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

                raise TokenRequestError(self._log.create_error(return_error_string), error_response)

            else:
                self._handle_get_device_code_response(resp.text)

        except Exception as exp:
            self._log.error("{0} request failed".format(operation), exp)
            raise exp

    def get_token_with_polling(self, oauth_parameters, refresh_internal, expires_in):
        token_response = {}

        token_url = self._create_token_url()
        url_encoded_code_request = urlencode(oauth_parameters)

        post_options = util.create_request_options(self, {'headers' : {'content-type': 'application/x-www-form-urlencoded'}})
        operation = "Get token with device code"

        max_times_for_retry = math.floor(expires_in/refresh_internal)
        for _ in range(int(max_times_for_retry)):
            if self._cancel_polling_request:
                raise ValueError('Polling_Request_Cancelled') #TODO: ask rich for the exception types

            resp = requests.post(token_url.geturl(), data=url_encoded_code_request, headers=post_options['headers'])
            util.log_return_correlation_id(self._log, operation, resp)

            # 2 possible bugs found during porting
            #1. https://github.com/AzureAD/azure-activedirectory-library-for-nodejs/blob/master/lib/oauth2client.js#L363, 
            #  the condition should be the opposite
            #2. https://github.com/AzureAD/azure-activedirectory-library-for-nodejs/blob/master/lib/oauth2client.js#L411
            #  the field naming is wrong, should use the counter part's name with "_" 
            # confirm whether the if logic is right
            wire_response = {} 
            if not util.is_http_success(resp.status_code):
                wire_response = json.loads(resp.text) # on error, the body should be json already 

            error = wire_response.get(OAuth2.DeviceCodeResponseParameters.ERROR)
            if error:
                if error == 'authorization_pending':
                    time.sleep(refresh_internal)
                    continue
                else:
                    raise ValueError(error)
            else:
                try:
                    token_response = self._validate_token_response(resp.text)
                except Exception as exp:
                    self._log.error("Error validating get token response", exp)
                    raise exp
                return token_response

        raise TimeoutError()

    def cancel_polling_request(self):
        self._cancel_polling_request = True

