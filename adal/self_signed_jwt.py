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

import time
import datetime
import uuid
import jwt
import base64
import re

from .constants import Jwt
from .log import Logger
from . import util

class SelfSignedJwt(object):

    NumCharIn128BitHexString = 128/8*2
    numCharIn160BitHexString = 160/8*2
    ThumbprintRegEx = "^[a-f\d]*$"

    def __init__(self, call_context, authority, client_id):
        self._log = Logger('SelfSignedJwt', call_context['log_context'])
        self._call_context = call_context

        self._authortiy = authority
        self._token_endpoint = authority.token_endpoint
        self._client_id = client_id

    def _get_date_now(self):
        return datetime.datetime.now()

    def _get_new_jwt_id(self):
        return str(uuid.uuid4())

    def _create_x5t_value(self, thumbprint):
        hex_str = thumbprint.replace(':', '').replace(' ', '')
        b64_str = base64.urlsafe_b64encode(hex_str.encode())
        return b64_str.decode()

    def _create_header(self, thumbprint):
        x5t = self._create_x5t_value(thumbprint)
        header = {'typ':'JWT', 'alg':'RS256', 'x5t':x5t}

        self._log.debug("Creating self signed JWT header. x5t: {0}".format(x5t))

        return header

    def _create_payload(self):

        now = self._get_date_now()
        minutes = datetime.timedelta(0, 0, 0, 0, Jwt.SELF_SIGNED_JWT_LIFETIME)
        expires = now + minutes

        self._log.debug('Creating self signed JWT payload. Expires: {0} NotBefore: {1}'.format(expires, now))

        jwt_payload = {}
        jwt_payload[Jwt.AUDIENCE] = self._token_endpoint
        jwt_payload[Jwt.ISSUER] = self._client_id
        jwt_payload[Jwt.SUBJECT] = self._client_id
        jwt_payload[Jwt.NOT_BEFORE] = int(time.mktime(now.timetuple()))
        jwt_payload[Jwt.EXPIRES_ON] = int(time.mktime(expires.timetuple()))
        jwt_payload[Jwt.JWT_ID] = self._get_new_jwt_id()

        return jwt_payload

    def _raise_on_invalid_jwt_signature(self, encoded_jwt):
        segments = encoded_jwt.split('.')
        if len(segments) < 3 or not segments[2]:
            raise self._log.create_error('Failed to sign JWT. This is most likely due to an invalid certificate.')

    def _raise_on_invalid_thumbprint(self, thumbprint):

        thumbprint_sizes = [self.NumCharIn128BitHexString, self.numCharIn160BitHexString]
        if len(thumbprint) not in thumbprint_sizes or not re.search(self.ThumbprintRegEx, thumbprint):
            raise self._log.create_error("The thumbprint does not match a known format")

    def _sign_jwt(self, header, payload, certificate):
        # TODO: Might want to load the cert and get the string proper.
        cert_start_str = '-----BEGIN RSA PRIVATE KEY-----'
        cert_end_str = '-----END RSA PRIVATE KEY-----\n'
        if not certificate.startswith(cert_start_str):
            raise Exception("Invalid Certificate: Expected Start of Certificate to be '{}'".format(cert_start_str))
        if not certificate.endswith(cert_end_str):
            raise Exception("Invalid Certificate: Expected End of Certificate to be '{}'".format(cert_end_str))

        # Strip '-----BEGIN RSA PRIVATE KEY-----' and '-----END RSA PRIVATE KEY-----'
        cert_string = "".join(certificate.strip().split("\n")[1:-1])
        cert_string_64 = base64.urlsafe_b64encode(cert_string.encode())

        encoded_jwt = self._encode_jwt(payload, cert_string_64, header)
        self._raise_on_invalid_jwt_signature(encoded_jwt)
        return encoded_jwt

    def _encode_jwt(self, payload, certificate, header):
        return jwt.encode(payload, certificate, headers=header).decode()

    def _reduce_thumbprint(self, thumbprint):

        canonical = thumbprint.lower().replace(' ', '').replace(':', '')
        self._raise_on_invalid_thumbprint(canonical)
        return canonical

    def create(self, certificate, thumbprint):
        thumbprint = self._reduce_thumbprint(thumbprint)
        header = self._create_header(thumbprint)
        payload = self._create_payload()
        signed_jwt = self._sign_jwt(header, payload, certificate)
        return signed_jwt
