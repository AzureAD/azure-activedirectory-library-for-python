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
class Errors:
    # Constants
    ERROR_VALUE_NONE = '{0} should not be None.'
    ERROR_VALUE_EMPTY_STRING = '{0} should not be "".'
    ERROR_RESPONSE_MALFORMED_XML = 'The provided response string is not well formed XML.'

class OAuth2Parameters(object):

    GRANT_TYPE = 'grant_type'
    CLIENT_ASSERTION = 'client_assertion'
    CLIENT_ASSERTION_TYPE = 'client_assertion_type'
    CLIENT_ID = 'client_id'
    CLIENT_SECRET = 'client_secret'
    REDIRECT_URI = 'redirect_uri'
    RESOURCE = 'resource'
    CODE = 'code'
    SCOPE = 'scope'
    ASSERTION = 'assertion'
    AAD_API_VERSION = 'api-version'
    USERNAME = 'username'
    PASSWORD = 'password'
    REFRESH_TOKEN = 'refresh_token'


class OAuth2GrantType(object):

    AUTHORIZATION_CODE = 'authorization_code'
    REFRESH_TOKEN = 'refresh_token'
    CLIENT_CREDENTIALS = 'client_credentials'
    JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    PASSWORD = 'password'
    SAML1 = 'urn:ietf:params:oauth:grant-type:saml1_1-bearer'
    SAML2 = 'urn:ietf:params:oauth:grant-type:saml2-bearer'


class OAuth2ResponseParameters(object):

    CODE = 'code'
    TOKEN_TYPE = 'token_type'
    ACCESS_TOKEN = 'access_token'
    ID_TOKEN = 'id_token'
    REFRESH_TOKEN = 'refresh_token'
    CREATED_ON = 'created_on'
    EXPIRES_ON = 'expires_on'
    EXPIRES_IN = 'expires_in'
    RESOURCE = 'resource'
    ERROR = 'error'
    ERROR_DESCRIPTION = 'error_description'


class OAuth2Scope(object):

    OPENID = 'openid'


class OAuth2(object):

    Parameters = OAuth2Parameters()
    GrantType = OAuth2GrantType()
    ResponseParameters = OAuth2ResponseParameters()
    Scope = OAuth2Scope()
    IdTokenMap = {
        'tid' : 'tenantId',
        'given_name' : 'givenName',
        'family_name' : 'familyName',
        'idp' : 'identityProvider'}


class TokenResponseFields(object):

    TOKEN_TYPE = 'tokenType'
    ACCESS_TOKEN = 'accessToken'
    REFRESH_TOKEN = 'refreshToken'
    CREATED_ON = 'createdOn'
    EXPIRES_ON = 'expiresOn'
    EXPIRES_IN = 'expiresIn'
    RESOURCE = 'resource'
    USER_ID = 'userId'
    ERROR = 'error'
    ERROR_DESCRIPTION = 'errorDescription'


class IdTokenFields(object):

    USER_ID = 'userId'
    IS_USER_ID_DISPLAYABLE = 'isUserIdDisplayable'
    TENANT_ID = 'tenantId'
    GIVE_NAME = 'givenName'
    FAMILY_NAME = 'familyName'
    IDENTITY_PROVIDER = 'identityProvider'

class Misc(object):

    MAX_DATE = 0xffffffff
    CLOCK_BUFFER = 5 # In minutes.


class Jwt(object):

    SELF_SIGNED_JWT_LIFETIME = 10 # 10 mins in mins
    AUDIENCE = 'aud'
    ISSUER = 'iss'
    SUBJECT = 'sub'
    NOT_BEFORE = 'nbf'
    EXPIRES_ON = 'exp'
    JWT_ID = 'jti'


class UserRealm(object):

    federation_protocol_type = {
        'WSFederation' : 'wstrust',
        'SAML2' : 'saml20',
        'Unknown' : 'unknown'
      }

    account_type = {
        'Federated' : 'federated',
        'Managed' : 'managed',
        'Unknown' : 'unknown'
      }


class Saml(object):

    TokenTypeV1 = 'urn:oasis:names:tc:SAML:1.0:assertion'
    TokenTypeV2 = 'urn:oasis:names:tc:SAML:2.0:assertion'


class XmlNamespaces(object):
    namespaces = {
        'wsdl'   :'http://schemas.xmlsoap.org/wsdl/',
        'sp'     :'http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702',
        'sp2005' :'http://schemas.xmlsoap.org/ws/2005/07/securitypolicy',
        'wsu'    :'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
        'wsa10'  :'http://www.w3.org/2005/08/addressing',
        'http'   :'http://schemas.microsoft.com/ws/06/2004/policy/http',
        'soap12' :'http://schemas.xmlsoap.org/wsdl/soap12/',
        'wsp'    :'http://schemas.xmlsoap.org/ws/2004/09/policy',
        's'      :'http://www.w3.org/2003/05/soap-envelope',
        'wsa'    :'http://www.w3.org/2005/08/addressing',
        'wst'    :'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
        'trust' : "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
        'saml' : "urn:oasis:names:tc:SAML:1.0:assertion",

    }

class MexNamespaces(object):
    TRANSPORT_BINDING_XPATH = 'wsp:ExactlyOne/wsp:All/sp:TransportBinding'
    TRANSPORT_BINDING_2005_XPATH = 'wsp:ExactlyOne/wsp:All/sp2005:TransportBinding'

    SOAP_ACTION_XPATH = 'wsdl:operation/soap12:operation'
    RST_SOAP_ACTION = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue'
    SOAP_TRANSPORT_XPATH = 'soap12:binding'
    SOAP_HTTP_TRANSPORT_VALUE = 'http://schemas.xmlsoap.org/soap/http'

    PORT_XPATH = 'wsdl:service/wsdl:port'
    ADDRESS_XPATH = 'wsa10:EndpointReference/wsa10:Address'


class Cache(object):

    HASH_ALGORITHM = 'sha256'


class HttpError(object):

    UNAUTHORIZED = 401


class AADConstants(object):

    WORLD_WIDE_AUTHORITY = 'login.windows.net'
    WELL_KNOWN_AUTHORITY_HOSTS = ['login.windows.net', 'login.microsoftonline.com', 'login.chinacloudapi.cn', 'login.cloudgovapi.us']
    INSTANCE_DISCOVERY_ENDPOINT_TEMPLATE = 'https://{authorize_host}/common/discovery/instance?authorization_endpoint={authorize_endpoint}&api-version=1.0'
    AUTHORIZE_ENDPOINT_PATH = '/oauth2/authorize'
    TOKEN_ENDPOINT_PATH = '/oauth2/token'


class AdalIdParameters(object):

    SKU = 'x-client-SKU'
    VERSION = 'x-client-Ver'
    OS = 'x-client-OS'
    CPU = 'x-client-CPU'
    PYTHON_SKU = 'Python'
