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

from datetime import datetime, timedelta
import uuid
import requests
import re
import json

from . import constants
from . import log
from . import util

try:
    from urllib.parse import quote, unquote, urlencode
    from urllib.parse import urlparse, urlsplit

except ImportError:
    from urllib import quote, unquote, urlencode
    from urlparse import urlparse, urlsplit

OAuth2Parameters = constants.OAuth2.Parameters;
OAuth2ResponseParameters = constants.OAuth2.ResponseParameters;
IdTokenMap = constants.OAuth2.IdTokenMap;
TokenResponseFields = constants.TokenResponseFields;
IdTokenFields = constants.IdTokenFields;

TOKEN_RESPONSE_MAP = {};
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.TOKEN_TYPE] = TokenResponseFields.TOKEN_TYPE
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.ACCESS_TOKEN] = TokenResponseFields.ACCESS_TOKEN
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.REFRESH_TOKEN] = TokenResponseFields.REFRESH_TOKEN
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.CREATED_ON] = TokenResponseFields.CREATED_ON
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.EXPIRES_ON] = TokenResponseFields.EXPIRES_ON
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.EXPIRES_IN] = TokenResponseFields.EXPIRES_IN
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.RESOURCE] = TokenResponseFields.RESOURCE
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.ERROR] = TokenResponseFields.ERROR
TOKEN_RESPONSE_MAP[OAuth2ResponseParameters.ERROR_DESCRIPTION] = TokenResponseFields.ERROR_DESCRIPTION

def map_fields(in_obj, out_obj, map):

    for key in in_obj.keys():
        if map.get(key):
            mapped = map[key]
            out_obj[mapped] = in_obj[key]

class OAuth2Client(object):

    def __init__(self, call_context, authority):

        self._token_endpoint = authority
        self._log = log.Logger("OAuth2Client", call_context['log_context'])
        self._call_context = call_context

    def _create_token_url(self):
        parameters = {}
        parameters['slice'] = 'testslice'
        parameters[OAuth2Parameters.AAD_API_VERSION] = '1.0'

        return urlparse('{}?{}'.format(self._token_endpoint, urlencode(parameters)))

    def _parse_optional_ints(self, obj, keys):
        for key in keys:
            try:
                obj[key] = int(obj[key])
            except ValueError:
                raise self._log.create_error("{0} could not be parsed as an int".format(key))
            except KeyError:
                # if the key isn't present we can just continue
                pass

    def _crack_jwt(self, jwt_token):

        id_token_parts_reg = "^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$"
        matches = re.search(id_token_parts_reg, jwt_token)
        if not matches or len(matches.groups()) < 3:
            self._log.warn("The returned id_token is not parsable")
            return

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
        extracted_values.update(self._get_user_id(id_token))

        map_fields(id_token, extracted_values, IdTokenMap)
        return extracted_values

    def _parse_id_token(self, encoded_token):

        cracked_token = self._crack_jwt(encoded_token)
        if not cracked_token:
            return

        id_token = None
        try:
            b64_id_token = cracked_token['JWSPayload']
            b64_decoded = util.base64_decode_string_urlsafe(b64_id_token)
            if not b64_decoded:
                self._log.warn('The returned id_token could not be base64 url safe decoded.')
                return

            id_token = json.loads(b64_decoded)

        except Exception as exp:
            self._log.warn("The returned id_token could not be decoded: {0}".format(exp))
            return

        return self._extract_token_values(id_token)

    def _validate_token_response(self, body):

        wire_response = None
        token_response = {}

        try:
            wire_response = json.loads(body)
        except Exception as exp:
            raise ValueError('The token response returned from the server is unparseable as JSON')

        int_keys = [
            OAuth2ResponseParameters.EXPIRES_ON,
            OAuth2ResponseParameters.EXPIRES_IN,
            OAuth2ResponseParameters.CREATED_ON
          ]

        self._parse_optional_ints(wire_response, int_keys)

        expires_in = wire_response.get(OAuth2ResponseParameters.EXPIRES_IN)
        if expires_in:
            now = datetime.now()
            soon = timedelta(seconds=expires_in)
            wire_response[OAuth2ResponseParameters.EXPIRES_ON] = str(now + soon)

        created_on = wire_response.get(OAuth2ResponseParameters.CREATED_ON)
        if created_on:
            temp_date = datetime.fromtimestamp(created_on)
            wire_response[OAuth2ResponseParameters.CREATED_ON] = str(temp_date)

        if not wire_response.get(OAuth2ResponseParameters.TOKEN_TYPE):
            raise self._log.create_error('wire_response is missing token_type')

        if not wire_response.get(OAuth2ResponseParameters.ACCESS_TOKEN):
            raise self._log.create_error('wire_response is missing access_token')

        map_fields(wire_response, token_response, TOKEN_RESPONSE_MAP)

        if wire_response.get(OAuth2ResponseParameters.ID_TOKEN):
            id_token = self._parse_id_token(wire_response[OAuth2ResponseParameters.ID_TOKEN])
            if id_token:
                token_response.update(id_token)

        return token_response

    def _handle_get_token_response(self, response, body, callback):

        token_response = None
        try:
            token_response = self._validate_token_response(body)
        except Exception as exp:
            self._log.error("Error validating get token response", exp)
            callback(exp, None)

        callback(None, token_response)

    def get_token(self, oauth_parameters, callback):

        token_url = self._create_token_url()
        url_encoded_token_request = urlencode(oauth_parameters)

        post_options = util.create_request_options(self, {'headers' : {'content-type': 'application/x-www-form-urlencoded'}})
        operation = "Get Token"

        try:
            resp = requests.post(token_url.geturl(), data=url_encoded_token_request, headers=post_options['headers'])
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
                self._handle_get_token_response(resp, resp.text, callback)

        except Exception as exp:
            self._log.error("{0} request failed".format(operation), exp)
            callback(exp, None)
            return