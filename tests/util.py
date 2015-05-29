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

import os
import re
import adal

from adal import log

from datetime import datetime, timedelta
import dateutil.parser
import time

import httpretty
import json

try:
    from urllib.parse import quote, unquote, urlencode
    from urllib.parse import urlparse, urlsplit

except ImportError:
    from urllib import quote, unquote, urlencode
    from urlparse import urlparse, urlsplit

_dirname = os.path.dirname(__file__)

success_response = {
  'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9.eyJhdWQiOiIwMDAwMDAwMi0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82MmYwMzQ3MS02N2MxLTRjNTAtYjlkMS0xMzQ1MDc5ZDk3NzQvIiwiaWF0IjoxMzc4NjAxMTY4LCJuYmYiOjEzNzg2MDExNjgsImV4cCI6MTM3ODYyOTk2OCwidmVyIjoiMS4wIiwidGlkIjoiNjJmMDM0NzEtNjdjMS00YzUwLWI5ZDEtMTM0NTA3OWQ5Nzc0Iiwib2lkIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3Iiwic3ViIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3IiwiYXBwaWQiOiI1YzI1ZDFiZi1iMjMyLTQwMzUtYjZiOS0yYjdlN2U4MzQ2ZDYiLCJhcHBpZGFjciI6IjEifQ.qXM7f9TTiLApxVMwaSrISQQ6UAnfKvKhoIlN9rB0Eff2VXvIWKGRsclPkMQ5x42BQz2N6pSXEsN-LsNCZlQ76Rc3rVRONzeCYh7q_NXcCJG_d6SJTtV5GBfgqFlgT8UF5rblabbMdOiOrddvJm048hWt2Nm3qD3QjQdPBlD7Ksn-lUR1jEJPIqDaBjGom8RawrZTW6X1cy1Kr8mEYFkxcbU91k_RZUumONep9FTR8gfPkboeD8zyvOy64UeysEtcuaNCfhHSBFcwC8MwjUr5r_T7au7ywAcYDOVgoa7oF_dN1JNweiDoNNZ9tyUS-RY3sa3-gXk77gRxpA4CkpittQ',
  'token_type': 'Bearer',
  'expires_in': 28800,
  'resource': '00000002-0000-0000-c000-000000000000',
}

refresh_token = 'AwABAAAAvPM1KaPlrEqdFSBzjqfTGCDeE7YHWD9jkU2WWYKLjxu928QAbkoFyWpgJLFcp65DcbBqOSYVq5Ty_60YICIdFw61SG4-eT1nWHNOPdzsL2ZzloUsp2DpqlIr1s5Z3953oQBi7dOqiHk37NXQqmNEJ7MfmDp6w3EOa29EPARvjGIHFgtICW1-Y82npw1v1g8Ittb02pksNU2XzH2X0E3l3TuSZWsX5lpl-kfPOc8zppU6bwvT-VOPHZVVLQedDIQZyOiFst9HLUjbiIvBgV7tNwbB4H5yF56QQscz49Nrb3g0ibuNDo7efFawLzNoVHzoTrOTcCGSG1pt8Z-npByrEe7vg1o4nNFjspuxlyMGdnYRAnaZfvgzqROP_m7ZqSd6IAA'

success_response_with_refresh = {
  'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9.eyJhdWQiOiIwMDAwMDAwMi0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82MmYwMzQ3MS02N2MxLTRjNTAtYjlkMS0xMzQ1MDc5ZDk3NzQvIiwiaWF0IjoxMzc4NjAxMTY4LCJuYmYiOjEzNzg2MDExNjgsImV4cCI6MTM3ODYyOTk2OCwidmVyIjoiMS4wIiwidGlkIjoiNjJmMDM0NzEtNjdjMS00YzUwLWI5ZDEtMTM0NTA3OWQ5Nzc0Iiwib2lkIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3Iiwic3ViIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3IiwiYXBwaWQiOiI1YzI1ZDFiZi1iMjMyLTQwMzUtYjZiOS0yYjdlN2U4MzQ2ZDYiLCJhcHBpZGFjciI6IjEifQ.qXM7f9TTiLApxVMwaSrISQQ6UAnfKvKhoIlN9rB0Eff2VXvIWKGRsclPkMQ5x42BQz2N6pSXEsN-LsNCZlQ76Rc3rVRONzeCYh7q_NXcCJG_d6SJTtV5GBfgqFlgT8UF5rblabbMdOiOrddvJm048hWt2Nm3qD3QjQdPBlD7Ksn-lUR1jEJPIqDaBjGom8RawrZTW6X1cy1Kr8mEYFkxcbU91k_RZUumONep9FTR8gfPkboeD8zyvOy64UeysEtcuaNCfhHSBFcwC8MwjUr5r_T7au7ywAcYDOVgoa7oF_dN1JNweiDoNNZ9tyUS-RY3sa3-gXk77gRxpA4CkpittQ',
  'token_type': 'Bearer',
  'expires_in': 28800,
  'resource': '00000002-0000-0000-c000-000000000000',
  'scope' : '62e90394-69f5-4237-9190-012177145e10',
  'refresh_token' : refresh_token
}

encoded_id_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInVuaXF1ZV9uYW1lIjoicnJhbmRhbGxAcnJhbmRhbGxhYWQxLm9ubWljcm9zb2Z0LmNvbSIsInN1YiI6IjRnVHY0RXRvWVctRFRvdzBiRG5KZDFBQTRzZkNoQmJqZXJtcXQ2UV9aYTQiLCJmYW1pbHlfbmFtZSI6IlJhbmRhbGwiLCJnaXZlbl9uYW1lIjoiUmljaCJ9.'

parsed_id_token = {
  'tenantId' : 'cceba14c-6a00-49ac-b806-84de52bf1d42',
  'userId' : 'rrandall@rrandallaad1.onmicrosoft.com',
  'givenName' : 'Rich',
  'familyName' : 'Randall',
  'isUserIdDisplayable' : True
}

decoded_id_token = {
  'aud': 'e958c09a-ac37-4900-b4d7-fb3eeaf7338d',
  'iss': 'https://sts.windows.net/cceba14c-6a00-49ac-b806-84de52bf1d42/',
  'iat': 1391645458,
  'nbf': 1391645458,
  'exp': 1391649358,
  'ver': '1.0',
  'tid': 'cceba14c-6a00-49ac-b806-84de52bf1d42',
  'oid': 'a443204a-abc9-4cb8-adc1-c0dfc12300aa',
  'upn': 'rrandall@rrandallaad1.onmicrosoft.com',
  'unique_name': 'rrandall@rrandallaad1.onmicrosoft.com',
  'sub': '4gTv4EtoYW-DTow0bDnJd1AA4sfChBbjermqt6Q_Za4',
  'family_name': 'Randall',
  'given_name': 'Rich'
}

encoded_id_token_url_safe = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiJlOTU4YzA5YS1hYzM3LTQ5MDAtYjRkNy1mYjNlZWFmNzMzOGQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jY2ViYTE0Yy02YTAwLTQ5YWMtYjgwNi04NGRlNTJiZjFkNDIvIiwiaWF0IjoxMzkxNjQ1NDU4LCJuYmYiOjEzOTE2NDU0NTgsImV4cCI6MTM5MTY0OTM1OCwidmVyIjoiMS4wIiwidGlkIjoiY2NlYmExNGMtNmEwMC00OWFjLWI4MDYtODRkZTUyYmYxZDQyIiwib2lkIjoiYTQ0MzIwNGEtYWJjOS00Y2I4LWFkYzEtYzBkZmMxMjMwMGFhIiwidXBuIjoiZm9vYmFyQHNvbWVwbGFjZWVsc2UuY29tIiwidW5pcXVlX25hbWUiOiJycmFuZGFsbEBycmFuZGFsbGFhZDEub25taWNyb3NvZnQuY29tIiwic3ViIjoiNGdUdjRFdG9ZVy1EVG93MGJEbkpkMUFBNHNmQ2hCYmplcm1xdDZRX1phNCIsImZhbWlseV9uYW1lIjoiUmFuZGFsbCIsImdpdmVuX25hbWUiOiJSaTw_Y2gifQ==.'

parsed_id_token_url_safe = {
  'tenantId' : 'cceba14c-6a00-49ac-b806-84de52bf1d42',
  'userId' : 'foobar@someplaceelse.com',
  'givenName' : 'Ri<?ch',
  'familyName' : 'Randall',
  'isUserIdDisplayable' : True
}

decoded_token_url_safe_test = {
  'aud': 'e958c09a-ac37-4900-b4d7-fb3eeaf7338d',
  'iss': 'https://sts.windows.net/cceba14c-6a00-49ac-b806-84de52bf1d42/',
  'iat': 1391645458,
  'nbf': 1391645458,
  'exp': 1391649358,
  'ver': '1.0',
  'tid': 'cceba14c-6a00-49ac-b806-84de52bf1d42',
  'oid': 'a443204a-abc9-4cb8-adc1-c0dfc12300aa',
  'upn': 'foobar@someplaceelse.com',
  'unique_name': 'rrandall@rrandallaad1.onmicrosoft.com',
  'sub': '4gTv4EtoYW-DTow0bDnJd1AA4sfChBbjermqt6Q_Za4',
  'family_name': 'Randall',
  'given_name': 'Ri<?ch'
}

parameters = {
    'tenant': 'rrandallaad1.onmicrosoft.com',
    'clientId': 'clien&&???tId',
    'clientSecret': 'clientSecret*&^(?&',
    'resource': '00000002-0000-0000-c000-000000000000',
    'evoEndpoint': 'https://login.windows.net',
    'username': 'rrandall@rrandallaad1.onmicrosoft.com',
    'password': 'Atestpass!@#$',
    'authorityHosts': {
        'global': 'login.windows.net',
        'china': 'login.chinacloudapi.cn',
        'gov': 'login.cloudgovapi.us'
    }
}

parameters['refreshToken'] = refresh_token

# This is a default authority to be used in tests that don't care that there are multiple.
parameters['authority'] = parameters['evoEndpoint']
parameters['authorityTenant'] = parameters['authority'] + '/' + parameters['tenant']
parameters['adfsUrlNoPath'] = 'https://adfs.federatedtenant.com'
parameters['adfsMexPath'] = '/adfs/services/trust/mex'
parameters['adfsWsTrustPath'] = '/adfs/services/trust/13/usernamemixed'
parameters['adfsMex'] = parameters['adfsUrlNoPath'] + parameters['adfsMexPath']
parameters['adfsWsTrust'] = parameters['adfsUrlNoPath'] + parameters['adfsWsTrustPath']

parameters['successResponse'] = success_response
parameters['successResponseWithRefresh'] = success_response_with_refresh
parameters['authUrlResult'] = urlparse(parameters['evoEndpoint'] + '/' + parameters['tenant'])
parameters['authUrl'] = parameters['authUrlResult'].geturl()

parameters['tokenPath'] = '/oauth2/token'
parameters['tokenUrlPath'] = parameters['authUrlResult'].path + parameters['tokenPath']
parameters['authorizePath'] = '/oauth/authorize'
parameters['authorizeUrlPath'] = parameters['authUrlResult'].path + parameters['authorizePath']
parameters['authorizeUrl'] = parameters['authUrlResult'].geturl()
parameters['instanceDiscoverySuccessResponse'] = {
  'tenant_discovery_endpoint' : parameters['authority']
}

parameters['userRealmPathTemplate'] = '/common/UserRealm/<user>'

parameters['userRealmResponseFederated'] = '{\"account_type\":\"federated\",\"federation_protocol\":\"wstrust\",\"federation_metadata_url\":\"'+parameters['adfsMex']+'\",\"federation_active_auth_url\":\"'+parameters['adfsWsTrust']+'\",\"ver\":\"0.8\"}'
parameters['userRealmResponseManaged'] = '{\"account_type\":\"managed\",\"federation_protocol\":\"wstrust\",\"federation_metadata_url\":\"'+parameters['adfsMex']+'\",\"federation_active_auth_url\":\"'+parameters['adfsWsTrust']+'\",\"ver\":\"0.8\"}'
parameters['MexFile'] = os.path.join(_dirname, '/mex/common.mex.xml')

parameters['RSTRFile'] = os.path.join(_dirname, '/wstrust/common.rstr.xml')
parameters['AssertionFile'] = os.path.join(_dirname, '/wstrust/common.base64.encoded.assertion.txt')
parameters['logContext'] = { 'correlation_id' : 'test-correlation-id-123456789' }
parameters['callContext'] = { 'log_context' : parameters['logContext'] }

def get_self_signed_cert():
    cert_file = os.path.join(_dirname, "data/self-signed-cert.pem")
    with open(cert_file) as private_pem:
        return private_pem.read()

parameters['certHash'] = 'C1:5D:EA:86:56:AD:DF:67:BE:80:31:D8:5E:BD:DC:5A:D6:C4:36:E1'
parameters['nowDate'] = datetime.fromtimestamp(1418433646.179)
parameters['jwtId'] = '09841beb-a2c2-4777-a347-34ef055238a8'
parameters['expectedJwt'] = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IndWM3FobGF0MzJlLWdESFlYcjNjV3RiRU51RSJ9.eyJhdWQiOiJodHRwczovL2xvZ2luLndpbmRvd3MubmV0L3JyYW5kYWxsYWFkMS5vbm1pY3Jvc29mdC5jb20vb2F1dGgyL3Rva2VuIiwiaXNzIjoiY2xpZW4mJj8_P3RJZCIsInN1YiI6ImNsaWVuJiY_Pz90SWQiLCJuYmYiOjE0MTg0MzM2NDYsImV4cCI6MTQxODQzNDI0NiwianRpIjoiMDk4NDFiZWItYTJjMi00Nzc3LWEzNDctMzRlZjA1NTIzOGE4In0.dgF0TRlcASgTMp_1dlm8vd7tudr6n40VeuOQGFnz566s3n76WR_jJDBBBKlYeqc9gwCPFOzrLVAJehVYZ3N7YPzVdulf47rLoQdAp8R_p4Q4hdBZuIzfgDWwXjnP9x_NlfzezEYE4r8KTS2g5BBzPmx538AfIdNM93hWIxQySZGWY5UAhTkT1qE1ce1Yjo1M2HqzEJhTg5TTyfrnDtNxFxmzYhSyA9B41lB5kBuJTXUWXPrr-6eG8cEUOS-iiH7YB1Tf4J7_9JQloevTiOrfv4pSp6xLLXm2ntNBg3gaKsGKdYd-3tsCG0mHn7BzL0b-QCLalkUr8KtgtLqkxuAiLQ'
parameters['cert'] = get_self_signed_cert()

correlation_id_regex = re.compile("[^\s]+")

def set_correlation_id(correlation_id):
    correlation_id_regex = correlation_id if correlation_id else correlation_id_regex

def turn_on_logging(level=log.LOGGING_LEVEL.DEBUG):
    log.set_logging_options({'level':level})

def reset_logging():
    pass

def clear_static_cache():
    pass

TOKEN_RESPONSE_MAP = {};
TOKEN_RESPONSE_MAP['token_type'] = 'tokenType'
TOKEN_RESPONSE_MAP['access_token'] = 'accessToken'
TOKEN_RESPONSE_MAP['refresh_token'] = 'refreshToken'
TOKEN_RESPONSE_MAP['created_on'] = 'createdOn'
TOKEN_RESPONSE_MAP['expires_on'] = 'expiresOn'
TOKEN_RESPONSE_MAP['expires_in'] = 'expiresIn'
TOKEN_RESPONSE_MAP['error'] = 'error'
TOKEN_RESPONSE_MAP['error_description'] = 'errorDescription'
TOKEN_RESPONSE_MAP['resource'] = 'resource'

def map_fields(in_obj, out_obj, map):
    for key in in_obj.keys():
        if map.get(key):
            mapped = map[key]
            out_obj[mapped] = in_obj[key]

def create_response(options = None, iteration = None):
    options = options if options else {}

    authority = options.get('authority', parameters['authorityTenant'])
    base_response = {
        'token_type' : 'Bearer',
        'expires_in': 28800
    }

    resource = options.get('resource', parameters['resource'])
    iterated = {
        'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9.eyJhdWQiOiIwMDAwMDAwMi0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82MmYwMzQ3MS02N2MxLTRjNTAtYjlkMS0xMzQ1MDc5ZDk3NzQvIiwiaWF0IjoxMzc4NjAxMTY4LCJuYmYiOjEzNzg2MDExNjgsImV4cCI6MTM3ODYyOTk2OCwidmVyIjoiMS4wIiwidGlkIjoiNjJmMDM0NzEtNjdjMS00YzUwLWI5ZDEtMTM0NTA3OWQ5Nzc0Iiwib2lkIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3Iiwic3ViIjoiZjEzMDkzNDEtZDcyMy00YTc1LTk2YzktNGIyMTMzMzk0Mjg3IiwiYXBwaWQiOiI1YzI1ZDFiZi1iMjMyLTQwMzUtYjZiOS0yYjdlN2U4MzQ2ZDYiLCJhcHBpZGFjciI6IjEifQ.qXM7f9TTiLApxVMwaSrISQQ6UAnfKvKhoIlN9rB0Eff2VXvIWKGRsclPkMQ5x42BQz2N6pSXEsN-LsNCZlQ76Rc3rVRONzeCYh7q_NXcCJG_d6SJTtV5GBfgqFlgT8UF5rblabbMdOiOrddvJm048hWt2Nm3qD3QjQdPBlD7Ksn-lUR1jEJPIqDaBjGom8RawrZTW6X1cy1Kr8mEYFkxcbU91k_RZUumONep9FTR8gfPkboeD8zyvOy64UeysEtcuaNCfhHSBFcwC8MwjUr5r_T7au7ywAcYDOVgoa7oF_dN1JNweiDoNNZ9tyUS-RY3sa3-gXk77gRxpA4CkpittQ',
        'resource' : resource
    }

    if not options.get('noRefresh'):
        if options.get('refreshedRefresh'):
            iterated['refresh_token'] = 'AwABAAAAvPM1KaPlrEqdFSBzjqfTGCDeE7YHWD9jkU2WWYKLjxu928QAbkoFyWp&yfPNft8DcbBqOSYVq5Ty_60YICIdFw61SG4-eT1nWHNOPdzsL2ZzloUsp2DpqlIr1s5Z3953oQBi7dOqiHk37NXQqmNEJ7MfmDp6w3EOa29EPARvjGIHFgtICW1-Y82npw1v1g8Ittb02pksNU2XzH2X0E3l3TuSZWsX5lpl-kfPOc8zppU6bwvT-VOPHZVVLQedDIQZyOiFst9HLUjbiIvBgV7tNwbB4H5yF56QQscz49Nrb3g0ibuNDo7efFawLzNoVHzoTrOTcCGSG1pt8Z-npByrEe7vg1o4nNFjspuxlyMGdnYRAnaZfvgzqROP_m7ZqSd6IAA'
        else:
            iterated['refresh_token'] = parameters['refreshToken']
    else:
        iterated['refresh_token'] = None

    if iteration:
        for key in iterated.keys():
            iterated[key] = iterated[key] + iteration

    base_response.update(iterated)

    if options.get('mrrt'):
        del base_response['resource']

    date_now = datetime.now()
    wire_response = dict(base_response)
    wire_response['created_on'] = time.mktime(date_now.timetuple())

    decoded_response = {}
    map_fields(wire_response, decoded_response, TOKEN_RESPONSE_MAP)
    decoded_response['createdOn'] = date_now

    if not options.get('noIdToken') and options.get('urlSafeUserId') is not None:
        wire_response['id_token'] = options['urlSafeUserId'] if encoded_id_token_url_safe else encoded_id_token
        parsed_user_info = options.get['urlSafeUserId'] if parsed_id_token_url_safe else parsed_id_token
        decoded_response.update(parsed_user_info)

    if options.get('expired'):
        expires_on_date = datetime.now() - timedelta(1)
    else:
        expires_on_date = datetime.now() + timedelta(seconds=decoded_response.get('expiresIn',0))

    decoded_response['expiresOn'] = str(expires_on_date)

    cached_response = dict(decoded_response)
    cached_response['_clientId'] = parameters['clientId']
    cached_response['_authority'] = authority
    cached_response['resource'] = iterated['resource']

    if options.get('mrrt'):
        cached_response['isMRRT'] = True

    return {
    'wireResponse' : wire_response,
    'decodedResponse' : decoded_response,
    'cachedResponse' : cached_response,
    'decodedIdToken' : decoded_id_token,
    'resource' : iterated['resource'],
    'refreshToken' : iterated['refresh_token'],
    'clientId' : cached_response['_clientId'],
    'authority' : authority
  }

def compare_query_strings(left, right):
    left_params = urlencode(left)
    right_params = urlencode(right)
    return left_params == right_params

def filter_query_strings(expected, received):
    return expected if compare_query_strings(expected, received) else received

def remove_query_string_if_matching(path, query):
    path_url = urlparse(path)
    return path_url.path if compare_query_strings(path_url.query, query) else path

def val_exists(val):
    return val if val else False

def match_standard_request_headers(mock_request):
    matches = []
    request_id = correlation_id_regex.match(mock_request.headers.get('client-request-id'))

    matches.append(mock_request.headers.get('x-client-SKU') == 'Python')
    matches.append(mock_request.headers.get('x-client-Ver', "").startswith('0.'))
    matches.append(mock_request.headers.get('x-client-OS') != None)
    matches.append(mock_request.headers.get('x-client-CPU') != None)
    matches.append(request_id != None)

    if not all(matches):
        raise AssertionError("Not all the standard request headers matched.")

def setup_expected_instance_discovery_request(http_code, discovery_host, return_doc, authority):
    protocol = 'https://'
    host = discovery_host
    pathname = '/common/discovery/instance'
    query = {}
    query['authorization_endpoint'] = authority
    query['api-version'] = '1.0'
    query_string = urlencode(query)

    url = "{}{}{}?{}".format(protocol, host, pathname, query_string)

    httpretty.register_uri(httpretty.GET, url, json.dumps(return_doc), status = http_code, content_type = 'text/json')

def setup_expected_oauth_response(queryParameters, tokenPath, httpCode, returnDoc, authorityEndpoint):
    query = urlencode(queryParameters)
    url = "{}{}?{}".format(authorityEndpoint, tokenPath, query)
    httpretty.register_uri(httpretty.POST, url, json.dumps(returnDoc), status = httpCode, content_type = 'text/json')

def setup_expected_client_cred_token_request_response(http_code, return_doc=None, authority_endpoint = None):
    auth_endpoint = authority_endpoint or parameters['authority']
    query = {
        'grant_type' : 'client_credentials',
        'client_id' : parameters['clientId'],
        'client_secret' : parameters['clientSecret'],
        'resource' : parameters['resource']
    }

    setup_expected_oauth_response(query, parameters['tokenPath'], http_code, return_doc, auth_endpoint)

def create_empty_adal_object():
    context = log.create_log_context()
    component = 'TEST'
    logger = log.Logger(component, context)
    call_context = {'log_context' : context }
    adal_object = { 'log' : logger, 'call_context' : call_context }
    return adal_object


def is_date_within_tolerance(date, expected_date = None):
    expected = expected_date or datetime.today()
    fiveBefore = expected - timedelta(0, 5)
    fiveAfter = expected + timedelta(0, 5)
    
    if date >= fiveBefore and date <= fiveAfter:
        return True

    return False

def is_expires_within_tolerance(expires_on):
    # Add the expected expires_in latency.
    expectedExpires = datetime.now() + timedelta(0, 28800)
    return is_date_within_tolerance(expires_on, expectedExpires);

def is_match_token_response(expected, received):
    expiresOn = received.get('expiresOn', None)
    createdOn = received.get('createdOn', None)

    if expiresOn:
        expiresOnTime = dateutil.parser.parse(expiresOn)
        if not is_expires_within_tolerance(expiresOnTime):
            return False

    if createdOn:
        createdOnTime = dateutil.parser.parse(createdOn)
        if not is_date_within_tolerance(createdOnTime):
            return False

    # Compare the expected and responses without the expires_on field as that was validated above.
    import copy
    received_copy = copy.deepcopy(received)
    received_copy.pop('expiresOn', None)
    received_copy.pop('createdOn', None)

    expected_copy = copy.deepcopy(expected)
    expected_copy.pop('expiresOn', None)
    expected_copy.pop('createdOn', None)

    if received_copy.get('clientId', None) and not expected_copy.get('clientId', None):
        received_copy.pop('clientId', None)
    
    # TODO: This should be modified in order to do an actual key to key comparison as dicts don't
    # guarantee order.
    isEqual = received_copy == expected_copy
    return isEqual