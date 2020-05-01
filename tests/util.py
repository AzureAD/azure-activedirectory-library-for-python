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
import re
import json
import time
import httpretty
from datetime import datetime, timedelta
import dateutil.parser

try:
    from urllib.parse import urlencode
    from urllib.parse import urlparse

except ImportError:
    from urllib import urlencode
    from urlparse import urlparse

from adal import log

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
  'isUserIdDisplayable' : True,
  'oid': 'a443204a-abc9-4cb8-adc1-c0dfc12300aa'
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
  'isUserIdDisplayable' : True,
  'oid': 'a443204a-abc9-4cb8-adc1-c0dfc12300aa'
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
    'evoEndpoint': 'https://login.microsoftonline.com/',
    'username': 'rrandall@rrandallaad1.onmicrosoft.com',
    'password': '<password>',
    'authorityHosts': {
        'global': 'login.microsoftonline.com',
        'china': 'login.chinacloudapi.cn',
        'gov': 'login.microsoftonline.us'
    }
}

parameters['refreshToken'] = refresh_token

# This is a default authority to be used in tests that don't care that there are multiple.
parameters['authority'] = parameters['evoEndpoint']
parameters['authorityTenant'] = parameters['authority'] + parameters['tenant']
parameters['adfsUrlNoPath'] = 'https://adfs.federatedtenant.com'
parameters['adfsMexPath'] = '/adfs/services/trust/mex'
parameters['adfsWsTrustPath'] = '/adfs/services/trust/13/usernamemixed'
parameters['adfsWsTrustPath2005'] = '/adfs/services/trust/2005/usernamemixed'
parameters['adfsMex'] = parameters['adfsUrlNoPath'] + parameters['adfsMexPath']
parameters['adfsWsTrust'] = parameters['adfsUrlNoPath'] + parameters['adfsWsTrustPath']
parameters['adfsWsTrust2005'] = parameters['adfsUrlNoPath'] + parameters['adfsWsTrustPath2005']

parameters['successResponse'] = success_response
parameters['successResponseWithRefresh'] = success_response_with_refresh
parameters['authUrlResult'] = urlparse(parameters['evoEndpoint'] + parameters['tenant'])
parameters['authUrl'] = parameters['authUrlResult'].geturl()

parameters['tokenPath'] = '/oauth2/token'
parameters['extraQP'] = '?api-version=1.0'
parameters['tokenUrlPath'] = parameters['authUrlResult'].path + parameters['tokenPath'] + parameters['extraQP']
parameters['deviceCodePath'] = '/oauth2/devicecode'
parameters['deviceCodeUrlPath'] = parameters['authUrlResult'].path + parameters['deviceCodePath'] + parameters['extraQP']
parameters['authorizePath'] = '/oauth/authorize'
parameters['authorizeUrlPath'] = parameters['authUrlResult'].path + parameters['authorizePath']
parameters['authorizeUrl'] = parameters['authUrlResult'].geturl()
parameters['instanceDiscoverySuccessResponse'] = {
  'tenant_discovery_endpoint' : parameters['authority']
}

parameters['userRealmPathTemplate'] = '/common/UserRealm/<user>'

parameters['userRealmResponseFederated'] = '{\"account_type\":\"federated\",\"federation_protocol\":\"wstrust\",\"federation_metadata_url\":\"'+parameters['adfsMex']+'\",\"federation_active_auth_url\":\"'+parameters['adfsWsTrust']+'\",\"ver\":\"0.8\"}'
parameters['userRealmResponseManaged'] = '{\"account_type\":\"managed\",\"federation_protocol\":\"wstrust\",\"federation_metadata_url\":\"'+parameters['adfsMex']+'\",\"federation_active_auth_url\":\"'+parameters['adfsWsTrust']+'\",\"ver\":\"0.8\"}'
parameters['MexFile'] = os.path.join(_dirname, 'mex/common.mex.xml')

parameters['RSTRFile'] = os.path.join(_dirname, 'wstrust/common.rstr.xml')
parameters['AssertionFile'] = os.path.join(_dirname, 'wstrust/common.base64.encoded.assertion.txt')
parameters['logContext'] = { 'correlation_id' : 'test-correlation-id-123456789' }
parameters['callContext'] = { 'log_context' : parameters['logContext'] }

# This is a dummy RSA private cert used for testing purpose.It does not represent valid credential.
# privatePem variable is a fake certificate in the form of a string.
def get_self_signed_cert():
    private_pem = ("-----BEGIN PRIVATE KEY-----\n"
                   "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLTKKMn3WJiDnc"
                   "8VuJPDr1kj9VYr9zdobMUSJ9YgRb6Rz05YiUOlSeNiMA6Y7yrpVbSxewIAkVC/gI"
                   "W/Ywp4FtR9j/SzQ91HIHvmKBrOAorpPDS0ZQ6nfeaBtZ14UIF16H/OvgyMkweBBd"
                   "7pIbF4i7ty3gdhFzpN2xd+qXTeDVMtxaQOM8RTAVp1RUpuNpPSIQxo9dLyOotcAe"
                   "Fj8uc0mMa0o6DbdxD26RiBIOgzcsYr5WUCMihmE3h1EIbXtQC5YwFnU9Q8OgupWz"
                   "i31QE1fbFgWzpjx1/KU9Yb8doWs1jwXSo4UGYecxiOKBrFuj0I6Kyelv9dfiayZF"
                   "GpwR+FmXAgMBAAECggEABmSxk/SL0LhtAWrBsy4muIRR45CIbswibxh6GjFT68QH"
                   "+heh1O+Eq7kOHsA5k54z6jwRUaOgRX4r3a9urZcG9fXVeCnYSb19nIq7NFLIdd8P"
                   "nIuoeXD2NhNWENw7PcbmXSZyEI6f7RtJgHq5M4ro7OZU1gNAhz9/DU61HO8BDBNP"
                   "9TT9h2Kf5cAHC79lrRs7Cj9yLK/JFFPFSyTEqxo9O6xHQfRv6X25rZeYo9JzGaqP"
                   "mwTvmheEqW7a75apBEpbzqD0f0jT4anaOSab0D10LyD9qEiCpzgDKG8Q31c0y9zS"
                   "Utk0suVR35abo22LdtvXMSyQMDfOOx3hqbUZ9c34uQKBgQD+oJUtfUYT9DBg/+jR"
                   "t/u+Tq/VnpolciQiIpIvUArhIFmOzLkt/hjH8ozOJlRrFADUWAE+pSWuAMdPjAsi"
                   "NGRYueAPQ29bqRF+5i0cJHXlxVNsqhF1SD5z/qaKU/MVL358v++g5shazQm45gUg"
                   "BeXyeRc++aFBTUAjUyoDOCh+bQKBgQDMZTacfAcGORL8TVvjq+0IJ6IppICmwRVU"
                   "FlZ/7HSJ+F1itggp0Kn9xzEk7SPgU8w0koysN+2189wn77PhQAAp1oGH2xvubXIz"
                   "nnAFpS9XbmzrG3JhHEVJqMe2qZ/pFOSqZxnNAekyWcE3BLamBBrMIx4wJBpmxVkf"
                   "EWUGSvolkwKBgDqQ8P8Pi2jXh7En64MhUFQLgUIfQtFOGaWIUhtzy6zQZgkEaat8"
                   "gHKtBVn9Uvl2FmLBAzhHgA0vvKg9S+pIJrSJvFGGbzyj/JQ1mTaZ5Ew/QNsDmxRg"
                   "04yWi/PRL142GF/VPebCbl8EPjI7Jf6hnKxS0df4TvDYNeJqJIWtCxNZAoGBAI04"
                   "rUfnhe7txklepcujgW1t/OQqzdzpcXQczv0qAcdGPDe0r+U8UAeQ9kqeMniPTXtR"
                   "ejKPngVmjUlmm/FZCAPgOrUEVcMiCZLSuHGeFRyipky3NQsVvmXLYNm7T0p67hcy"
                   "jygPVvE8BHygHBaOpXlAFl6Kw1cYqaAGo7d6XGVTAoGBAL0FucFmEAZOH7Bcnl30"
                   "JMXMcoedCAMMZG235cL2xBz6z+MzWVMkiZxblOVqAHRExGDoT01fymVte1OoKx7Q"
                   "SKiGNXCVBatkk7PlRUVnL0ziSwgYVxNX9eGNXZRBXUH3BuoYPlfdUMH36vgmukbT"
                   "Ui28YpkjQ5RY1UwUY6tk+Bka\n"
                    "-----END PRIVATE KEY-----")
    public_pem = ("MIICoTCCAYkCAgPoMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCUNMSS1Mb2dp"
                  "bjAiGA8yMDE4MTAxNzE2MTAxN1oYDzIwMTkxMDE3MTYxMDE5WjAUMRIwEAYDVQQD"
                  "DAlDTEktTG9naW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLTKKM"
                  "n3WJiDnc8VuJPDr1kj9VYr9zdobMUSJ9YgRb6Rz05YiUOlSeNiMA6Y7yrpVbSxew"
                  "IAkVC/gIW/Ywp4FtR9j/SzQ91HIHvmKBrOAorpPDS0ZQ6nfeaBtZ14UIF16H/Ovg"
                  "yMkweBBd7pIbF4i7ty3gdhFzpN2xd+qXTeDVMtxaQOM8RTAVp1RUpuNpPSIQxo9d"
                  "LyOotcAeFj8uc0mMa0o6DbdxD26RiBIOgzcsYr5WUCMihmE3h1EIbXtQC5YwFnU9"
                  "Q8OgupWzi31QE1fbFgWzpjx1/KU9Yb8doWs1jwXSo4UGYecxiOKBrFuj0I6Kyelv"
                  "9dfiayZFGpwR+FmXAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBADfEqXzcI/fs82T0"
                  "9B3H3lGWQL1JlcxOxD2TeMPtubDNllhZBT5GaYiw1LWAq+xJZZh+QPNxvZVw5Q/p"
                  "wgXo32maLNwjuhlDl/5bNNOMsxszRz60C2QQXzIaBxd6T2EUcnMQozu5y/33HT8k"
                  "k/ipBKbfmLP7Hgvs2xdhjHQcG61a2QP6qxD0UjVpXlgsL8wwc28ZSk1RqhxnHG0s"
                  "HRrRuwNhqWRe7JCGNkOwUghlemrqSuL3i6iAaeqipBqS0vVFGN8KS12jKYirEV5T"
                  "YkJ2HRrzSWEWbGhk+LnVis47nYRFzQB/sec/m+rpCpX6Spmiez6Yge2u874Oks/A"
                  "OGQyeYk=")

    return private_pem, public_pem

parameters['certHash'] = 'B8:D3:FC:F1:51:50:63:7F:B0:ED:EE:32:C5:A2:4B:A2:28:D8:93:91'
parameters['nowDate'] = datetime.fromtimestamp(1418433646.179)
parameters['jwtId'] = '09841beb-a2c2-4777-a347-34ef055238a8'
parameters['expectedJwtWithThumbprint'] = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6InVOUDg4VkZRWTMtdzdlNHl4YUpMb2lqWWs1RT0ifQ.eyJleHAiOjE0MTg0MzQyNDYsImF1ZCI6bnVsbCwiaXNzIjoiZDY4MzU3MTMtYjc0NS00OGQxLWJiNjItN2E4MjQ4NDc3ZDM1IiwianRpIjoiMDk4NDFiZWItYTJjMi00Nzc3LWEzNDctMzRlZjA1NTIzOGE4IiwibmJmIjoxNDE4NDMzNjQ2LCJzdWIiOiJkNjgzNTcxMy1iNzQ1LTQ4ZDEtYmI2Mi03YTgyNDg0NzdkMzUifQ.sV5CPEQjYqlnGXhv2f8ozCpAD281is1aOjOHZRKQlPe8zuRhEC4DnAv66QcrxA9HkPs3OAR1GWHnlgVL88uCcAbdEgFo7cAVaQQeRr90zlDMOMoZqULXnorbO90q91BrnJdbcygzsba4Z_FPzKAsJ7J8NXWfWcbkFGrisjuyi97Nm-nCCpjH1zM6gi3paGg_53GFb2S7xMv1lvB7LfPQMI8QvOC64kmVia-cr2NQoT9XLz2U_1ahCKidN2ozyCv09shRjfBu2QSeIctbv0BKVfQQCUnLuMQ-O4_NKY3THZn5hl5PvFDPjlI3X_Om58gPhwISkgtndGTMJ9W-H5z71Q'
parameters['expectedJwtWithPublicCert'] = 'eyJ4NWMiOiJNSUlDb1RDQ0FZa0NBZ1BvTUEwR0NTcUdTSWIzRFFFQkJRVUFNQlF4RWpBUUJnTlZCQU1NQ1VOTVNTMU1iMmRwYmpBaUdBOHlNREU0TVRBeE56RTJNVEF4TjFvWUR6SXdNVGt4TURFM01UWXhNREU1V2pBVU1SSXdFQVlEVlFRRERBbERURWt0VEc5bmFXNHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFETFRLS01uM1dKaURuYzhWdUpQRHIxa2o5VllyOXpkb2JNVVNKOVlnUmI2UnowNVlpVU9sU2VOaU1BNlk3eXJwVmJTeGV3SUFrVkMvZ0lXL1l3cDRGdFI5ai9TelE5MUhJSHZtS0JyT0FvcnBQRFMwWlE2bmZlYUJ0WjE0VUlGMTZIL092Z3lNa3dlQkJkN3BJYkY0aTd0eTNnZGhGenBOMnhkK3FYVGVEVk10eGFRT004UlRBVnAxUlVwdU5wUFNJUXhvOWRMeU9vdGNBZUZqOHVjMG1NYTBvNkRiZHhEMjZSaUJJT2d6Y3NZcjVXVUNNaWhtRTNoMUVJYlh0UUM1WXdGblU5UThPZ3VwV3ppMzFRRTFmYkZnV3pwangxL0tVOVliOGRvV3MxandYU280VUdZZWN4aU9LQnJGdWowSTZLeWVsdjlkZmlheVpGR3B3UitGbVhBZ01CQUFFd0RRWUpLb1pJaHZjTkFRRUZCUUFEZ2dFQkFEZkVxWHpjSS9mczgyVDA5QjNIM2xHV1FMMUpsY3hPeEQyVGVNUHR1YkRObGxoWkJUNUdhWWl3MUxXQXEreEpaWmgrUVBOeHZaVnc1US9wd2dYbzMybWFMTndqdWhsRGwvNWJOTk9Nc3hzelJ6NjBDMlFRWHpJYUJ4ZDZUMkVVY25NUW96dTV5LzMzSFQ4a2svaXBCS2JmbUxQN0hndnMyeGRoakhRY0c2MWEyUVA2cXhEMFVqVnBYbGdzTDh3d2MyOFpTazFScWh4bkhHMHNIUnJSdXdOaHFXUmU3SkNHTmtPd1VnaGxlbXJxU3VMM2k2aUFhZXFpcEJxUzB2VkZHTjhLUzEyaktZaXJFVjVUWWtKMkhScnpTV0VXYkdoaytMblZpczQ3bllSRnpRQi9zZWMvbStycENwWDZTcG1pZXo2WWdlMnU4NzRPa3MvQU9HUXllWWs9IiwieDV0IjoidU5QODhWRlFZMy13N2U0eXhhSkxvaWpZazVFPSIsImFsZyI6IlJTMjU2IiwidHlwIjoiSldUIn0.eyJqdGkiOiIwOTg0MWJlYi1hMmMyLTQ3NzctYTM0Ny0zNGVmMDU1MjM4YTgiLCJleHAiOjE0MTg0MzQyNDYsImF1ZCI6bnVsbCwic3ViIjoiZDY4MzU3MTMtYjc0NS00OGQxLWJiNjItN2E4MjQ4NDc3ZDM1IiwibmJmIjoxNDE4NDMzNjQ2LCJpc3MiOiJkNjgzNTcxMy1iNzQ1LTQ4ZDEtYmI2Mi03YTgyNDg0NzdkMzUifQ.ROcEKjjuKN0-iK4seRCYftvEh8F5Esj1Y3NJF0MbUGWZQYTRnjibJAnVkvmCqFSGT_mDFhasTM67pwAWtfYNP875UM87HG4aUyZG48pFojnWxnMMf9gBardPmpaDNi3U_iIGoTGVLR60JV30WjsOCkEJY79l68EMc5i6XqYtOSyJDlI0rn8ZTqoyVHQYqCwkTLDF0cqTrqK6HV9iWuiT0rq3LMP2lShwAhKaTYIeAAek5Bw5LwRR2mo9ybreq_02vCDxIQg0C3kBDGMU8GxQ2tAWMYSqnxNfrjgUhARDQYdZTjCyuq1kOb8QrHly29mPT7xdS7Xnc0IF6JZb1PXj0Q'
parameters['cert'], parameters['publicCert'] = get_self_signed_cert()

correlation_id_regex = re.compile("[^\s]+")

def set_correlation_id(correlation_id=None):
    global correlation_id_regex
    correlation_id_regex = correlation_id if correlation_id else correlation_id_regex

def turn_on_logging(level='DEBUG', handler = None):
    log.set_logging_options({
        'level' : level,
        'handler' : handler
        })

def reset_logging():
    pass

def clear_static_cache():
    pass

TOKEN_RESPONSE_MAP = {
    'token_type' : 'tokenType',
    'access_token' : 'accessToken',
    'refresh_token' : 'refreshToken',
    'created_on' : 'createdOn',
    'expires_on' : 'expiresOn',
    'expires_in' : 'expiresIn',
    'error' : 'error',
    'error_description' : 'errorDescription',
    'resource' : 'resource',
}

DEVICE_CODE_RESPONSE_MAP = {
    'device_code' : 'deviceCode',
    'user_code' : 'userCode',
    'verification_url' : 'verificationUrl',
    'interval' : 'interval',
    'expires_in' : 'expiresIn',
    'error' : 'error',
    'error_description' : 'errorDescription'
    }

def dicts_equal(expected, actual):
    '''
    Compares two dictionaries and returns an error message if something is wrong.
    None otherwise
    '''
    if not len(expected) == len(actual):
        return 'dicts are not the same length'

    shared_items = set(expected.keys()) & set(actual.keys())
    if not len(shared_items) == len(expected):
        return 'The provided dicts do not have the same keys'

    for i in expected.keys():
        expected_value = expected[i]
        actual_value = actual[i]

        if not expected_value == actual_value:
            return 'Not Equal: expected:{} actual:{}'.format(expected_value[i], actual_value[i])

    return None

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

    if not options.get('mrrt', False):
        del base_response['resource']

    date_now = datetime.now()
    wire_response = dict(base_response)
    wire_response['created_on'] = time.mktime(date_now.timetuple())

    decoded_response = {}
    map_fields(wire_response, decoded_response, TOKEN_RESPONSE_MAP)
    decoded_response['createdOn'] = str(date_now)

    if not options.get('noIdToken', None):
        if options.get('urlSafeUserId', None):
            wire_response['id_token'] = encoded_id_token_url_safe
            parsed_user_info = parsed_id_token_url_safe
        else:
            wire_response['id_token'] = encoded_id_token
            parsed_user_info = parsed_id_token

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

    if options.get('mrrt', False):
        cached_response['isMRRT'] = True

    return {
    'wireResponse' : wire_response,
    'decodedResponse' : decoded_response,
    'cachedResponse' : cached_response,
    'decodedIdToken' : decoded_id_token,
    'resource' : iterated['resource'],
    'refreshToken' : iterated['refresh_token'],
    'clientId' : cached_response['_clientId'],
    'authority' : authority,
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
    matches.append(mock_request.headers.get('x-client-SKU', None) == 'Python')
    assert mock_request.headers.get('x-client-Ver') is not None
    matches.append(mock_request.headers.get('x-client-OS', None) != None)
    matches.append(mock_request.headers.get('x-client-CPU', None) != None)
    request_id = correlation_id_regex.match(mock_request.headers.get('client-request-id'))
    matches.append(request_id != None)

    if not all(matches):
        raise AssertionError("Not all the standard request headers matched.")

def setup_expected_oauth_response(queryParameters, tokenPath, httpCode, returnDoc, authorityEndpoint):
    query = urlencode(queryParameters)
    url = "{}/{}?{}".format(authorityEndpoint.rstrip('/'), tokenPath.lstrip('/'), query)
    httpretty.register_uri(httpretty.POST, url, json.dumps(returnDoc), status = httpCode, content_type = 'text/json')

def setup_expected_client_cred_token_request_response(http_code, return_doc=None, authority_endpoint = None):
    auth_endpoint = authority_endpoint or parameters['authUrl']
    query = {
        'grant_type' : 'client_credentials',
        'client_id' : parameters['clientId'],
        'client_secret' : parameters['clientSecret'],
        'resource' : parameters['resource']
    }
    setup_expected_oauth_response(query, parameters['tokenPath'] + parameters['extraQP'], http_code, return_doc, auth_endpoint)

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

def setup_expected_user_realm_response(http_code, return_doc, authority=None):
    user_realm_authority = authority or parameters['authority']
    user_realm_authority = urlparse(user_realm_authority)

    # Get Base URL
    user_realm_authority = '{}://{}'.format(user_realm_authority.scheme, user_realm_authority.netloc)

    user_realm_path = parameters['userRealmPathTemplate'].replace('<user>', parameters['username'])
    query = 'api-version=1.0'
    url = '{}/{}?{}'.format(user_realm_authority.rstrip('/'), user_realm_path.lstrip('/'), query)

    httpretty.register_uri(httpretty.GET, url, return_doc)

def setup_expected_user_realm_response_common(federated):
    if federated:
        response_doc = parameters['userRealmResponseFederated']
    else:
        response_doc = parameters['userRealmResponseManaged']

    return setup_expected_user_realm_response(200, response_doc, parameters['authority'])

def setup_expected_refresh_token_request_response(http_code, return_doc, authority_endpoint=None, resource=None, client_secret=None):
    auth_endpoint = authority_endpoint or parameters['authority']

    query_parameters = {}
    query_parameters['grant_type'] = 'refresh_token'
    query_parameters['client_id'] = parameters['clientId']
    if client_secret:
        query_parameters['client_secret'] = client_secret

    if resource:
        query_parameters['resource'] = resource

    query_parameters['refresh_token'] = parameters['refreshToken']

    return setup_expected_oauth_response(query_parameters, parameters['tokenUrlPath'], http_code, return_doc, auth_endpoint)

def setup_expected_mex_wstrust_request_common():
    with open(parameters['MexFile']) as mex:
        mex_doc = mex.read()
    httpretty.register_uri(httpretty.GET, parameters['adfsUrlNoPath'] + parameters['adfsMexPath'], mex_doc)
    
    with open(parameters['RSTRFile']) as resr:
        rest_doc = resr.read()
    httpretty.register_uri(httpretty.POST, parameters['adfsUrlNoPath'] + parameters['adfsWsTrustPath'], rest_doc)

def create_empty_adal_object():
    context = log.create_log_context()
    component = 'TEST'
    logger = log.Logger(component, context)
    call_context = {'log_context' : context }
    adal_object = { 'log' : logger, 'call_context' : call_context }
    return adal_object

def is_date_within_tolerance(date, expected_date = None):
    expected = expected_date or datetime.today()
    min_range = expected - timedelta(0, 5000)
    max_range = expected + timedelta(0, 5000)

    if date >= min_range and date <= max_range:
        return True

    return False

def is_expires_within_tolerance(expires_on):
    # Add the expected expires_in latency.
    expectedExpires = datetime.now() + timedelta(0, 28800)
    return is_date_within_tolerance(expires_on, expectedExpires)

def is_match_token_response(expected, received):
    if not received:
        raise Exception("Token Response received is None")

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

    expect_empty = dicts_equal(expected_copy, received_copy)
    return expect_empty is None
