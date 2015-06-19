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

from . import authentication_context
from .authentication_context import (
    AuthenticationContext,
    get_ADAL_options,
    set_ADAL_options)
 
from . import log  
from .log import Logger
from . import authentication_parameters

from . import memory_cache
from .memory_cache import MemoryCache

from . import util
from adal.token_request import TokenRequest
from adal import argument

util.adal_init()

def create_authentication_context(authority, validate_authority):
    return AuthenticationContext(authority, validate_authority)

def acquire_token_with_username_password(
    username, 
    password, 
    authority = None,
    resource = None, 
    client_id = None, 
    validate_authority = True):
    '''
    Acquires a token when given a username and password combination

    Args:
        username (str): 
            Your username in the form user@domain.com.
        password (str): 
            Your password.
        authority (str, optional):
            Your authority with default 'https://login.windows.net/common'.
        resource (str, optional): 
            The resource you are accessing.  Defaults to '00000002-0000-0000-c000-000000000000'.
            Another common connection resource is 'https://management.core.windows.net/'.
        client_id (str, optional): 
            The id of your client. Defaults to '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
            This is the client id for xplat which should be on all tenants.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn', 
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable', 
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'
    '''
    authority = authority or _DefaultValues.authority
    resource = resource or _DefaultValues.resource
    client_id = client_id or _DefaultValues.client_id 

    argument.validate_string_param(resource, 'resource')
    argument.validate_string_param(username, 'username')
    argument.validate_string_param(password, 'password')
    argument.validate_string_param(client_id, 'client_id')
   
    context = create_authentication_context(authority, validate_authority)
    token_response = []
        
    def callback(err, tokenResponse):
        if err:
            raise Exception("Error:{} TokenResponse:{}".format(err, tokenResponse))
        token_response.append(tokenResponse)

    def token_func(context):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource)
        context.token_request._get_token_with_username_password(username, password, callback)

    context._acquire_token(callback, token_func)
    return token_response[0]

def acquire_token_with_client_credentials(
    client_secret,
    authority = None,
    resource = None, 
    client_id = None, 
    validate_authority = True):
    '''
    Acquires a token when given a username and password combination

    Args:
        client_secret (str):
            The client secret used to get the token.
        authority (str, optional):
            Your authority with default 'https://login.windows.net/common'.
        resource (str, optional): 
            The resource you are accessing.  Defaults to '00000002-0000-0000-c000-000000000000'.
            Another common connection resource is 'https://management.core.windows.net/'.
        client_id (str, optional): 
            The id of your client. Defaults to '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
            This is the client id for xplat which should be on all tenants.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn', 
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable', 
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'.
    '''
    authority = authority or _DefaultValues.authority
    resource = resource or _DefaultValues.resource
    client_id = client_id or _DefaultValues.client_id 

    argument.validate_string_param(resource, 'resource')
    argument.validate_string_param(client_id, 'client_id')
    argument.validate_string_param(client_secret, 'client_secret')
    
    context = create_authentication_context(authority, validate_authority)
    token_response = []
        
    def callback(err, tokenResponse):
        if err:
            raise Exception("Error:{} TokenResponse:{}".format(err, tokenResponse))
        token_response.append(tokenResponse)

    def token_func(context, extra=None):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource)
        context.token_request._get_token_with_client_credentials(client_secret, callback)

    context._acquire_token(callback, token_func)
    return token_response[0]

def acquire_token_with_authorization_code(
    authorization_code, 
    redirect_uri, 
    client_secret,
    authority = None,
    resource = None, 
    client_id = None, 
    validate_authority = True):
    '''
    Acquires a token when given a username and password combination

    Args:
        authorization_code (str): 
            The authorization code used to get a token.
        redirect_uri (str): 
            The URI to redirect to.
        client_secret (str):
            The client secret used to get the token.
        authority (str, optional):
            Your authority with default 'https://login.windows.net/common'.
        resource (str, optional): 
            The resource you are accessing.  Defaults to '00000002-0000-0000-c000-000000000000'.
            Another common connection resource is 'https://management.core.windows.net/'.
        client_id (str, optional): 
            The id of your client. Defaults to '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
            This is the client id for xplat which should be on all tenants.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn', 
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable', 
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'.
    '''
    authority = authority or _DefaultValues.authority
    resource = resource or _DefaultValues.resource
    client_id = client_id or _DefaultValues.client_id 

    argument.validate_string_param(resource, 'resource')
    argument.validate_string_param(authorization_code, 'authorization_code')
    argument.validate_string_param(redirect_uri, 'redirect_uri')
    argument.validate_string_param(client_id, 'client_id')
    argument.validate_string_param(client_secret, 'client_secret')
   
    context = create_authentication_context(authority, validate_authority)
    token_response = []
        
    def callback(err, tokenResponse):
        if err:
            raise Exception("Error:{} TokenResponse:{}".format(err, tokenResponse))
        token_response.append(tokenResponse)

    def token_func(context):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource, redirect_uri)
        context.token_request._get_token_with_authorization_code(authorization_code, client_secret, callback)

    context._acquire_token(callback, token_func)
    return token_response[0]

def acquire_token_with_refresh_token(
    refresh_token, 
    client_secret, 
    authority = None,
    resource = None, 
    client_id = None, 
    validate_authority = True):
    '''
    Acquires a token when given a username and password combination

    Args:
        refresh_token (str): 
            The refresh token for the token you are refreshing.
        client_secret (str):
            The client secret used to get the token.
        authority (str, optional):
            Your authority with default 'https://login.windows.net/common'
        resource (str, optional): 
            The resource you are accessing.  Defaults to '00000002-0000-0000-c000-000000000000'.
            Another common connection resource is 'https://management.core.windows.net/'.
        client_id (str, optional): 
            The id of your client. Defaults to '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
            This is the client id for xplat which should be on all tenants.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn', 
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable', 
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'.
    '''
    authority = authority or _DefaultValues.authority
    resource = resource or _DefaultValues.resource
    client_id = client_id or _DefaultValues.client_id 

    argument.validate_string_param(refresh_token, 'refresh_token')
    argument.validate_string_param(client_id, 'client_id')

    context = create_authentication_context(authority, validate_authority)
    token_response = []
        
    def callback(err, tokenResponse):
        if err:
            raise Exception("Error:{} TokenResponse:{}".format(err, tokenResponse))
        token_response.append(tokenResponse)

    def token_func(context):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource)
        context.token_request.get_token_with_refresh_token(refresh_token, client_secret, callback)

    context._acquire_token(callback, token_func)
    return token_response[0]

def acquire_token_with_client_certificate(
    certificate, 
    thumbprint,
    authority = None,
    resource = None, 
    client_id = None, 
    validate_authority = True):
    '''
    Acquires a token when given a username and password combination

    Args:
        certificate (str):
            The certificate for the token you are getting.
        thumbprint (str): 
            The thumbprint of the certificate.
        authority (str, optional):
            Your authority with default 'https://login.windows.net/common'.
        resource (str, optional): 
            The resource you are accessing.  Defaults to '00000002-0000-0000-c000-000000000000'.
            Another common connection resource is 'https://management.core.windows.net/'.
        client_id (str, optional): 
            The id of your client. Defaults to '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
            This is the client id for xplat which should be on all tenants.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn', 
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable', 
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'
    '''
    authority = authority or _DefaultValues.authority
    resource = resource or _DefaultValues.resource
    client_id = client_id or _DefaultValues.client_id 

    argument.validate_string_param(resource, 'resource')
    argument.validate_string_param(certificate, 'certificate')
    argument.validate_string_param(thumbprint, 'thumbprint')

    context = create_authentication_context(authority, validate_authority)
    token_response = []
        
    def callback(err, tokenResponse):
        if err:
            raise Exception("Error:{} TokenResponse:{}".format(err, tokenResponse))
        token_response.append(tokenResponse)

    def token_func(context):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource)
        context.token_request.get_token_with_certificate(certificate, thumbprint, callback)

    context._acquire_token(callback, token_func)
    return token_response[0]

class _DefaultValues:
    authority='https://login.windows.net/common'
    resource = '00000002-0000-0000-c000-000000000000' 
    client_id='04b07795-8ddb-461a-bbee-02f9e1bf7b46'