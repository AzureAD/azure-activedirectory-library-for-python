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

from . import authentication_context
from .authentication_context import AuthenticationContext

from . import log
from .log import Logger
from . import authentication_parameters

from adal.token_request import TokenRequest
from adal import argument

__version__ = '0.1.0'

'''
    Note:
        At the time of authoring the Azure Portal does not provide an easy way to enable Azure
        Resource Management permissions to the Application we use for this authentication.  Using
        the powershell commandlets you can run the following commands to enable the permissions.
            Switch-AzureMode -Name AzureResourceManager
            Add-AzureAccount # This will pop up a login dialog
             # Look at the subscriptions returned and put one on the line below
            Select-AzureSubscription -SubscriptionId ABCDEFGH-1234-1234-1234-ABCDEFGH
            New-AzureRoleAssignment -ServicePrincipalName http://PythonSDK -RoleDefinitionName Contributor

            TODO: We should provide the code to do this using the XPlat CLI
'''


def acquire_token_with_username_password(
    authority,
    username,
    password,
    client_id=None,
    resource=None,
    validate_authority=True
):
    '''
    Acquires a token when given a username and password combination.

    Args:
        authority (str):
            Your authority will have the form
            'https://login.windows.net/ABCDEFGH-1234-ABCD-1234-ABCDEFGHIJKL'.
            You must retrieve the this URI + GUID for your tenant.  You can find this on the Azure
            Active Directory Application Configure page and click view endpoints.  This string will
            be the root of the connection links given.
        username (str):
            Your username in the form user@domain.com.
        password (str):
            Your password.
        client_id (str, optional):
            The id of your client. For username password we use the XPlat Client Id by default.
        resource (str, optional):
            The resource you are accessing.  Defaults to 'https://management.core.windows.net/'.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn',
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable',
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'
    '''
    resource = resource or _DefaultValues.resource
    client_id = client_id or _DefaultValues.client_id

    argument.validate_string_param(authority, 'authority')
    argument.validate_string_param(client_id, 'client_id')
    argument.validate_string_param(username, 'username')
    argument.validate_string_param(password, 'password')
    argument.validate_string_param(resource, 'resource')

    context = AuthenticationContext(authority, validate_authority)
    token_responses = []

    def callback(err, token_response):
        if err:
            raise Exception("Error:{} token_response:{}".format(err, token_response))
        token_responses.append(token_response)

    def token_func(context):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource)
        context.token_request._get_token_with_username_password(username, password, callback)

    context._acquire_token(callback, token_func)
    return token_responses[0]

def acquire_token_with_client_credentials(
    authority,
    client_id,
    client_secret,
    resource=None,
    validate_authority=True
):
    '''
    Acquires a token when given a set of client credentials.

    Args:
        authority (str):
            Your authority will have the form
            'https://login.windows.net/ABCDEFGH-1234-ABCD-1234-ABCDEFGHIJKL'.
            You must retrieve the this URI + GUID for your tenant.  You can find this on the Azure
            Active Directory Application Configure page and click view endpoints.  This string will
            be the root of the connection links given.
        client_id (str):
            The id of your client. Found on the configure page of Azure Active Directory
            Applications.
        client_secret (str):
            The client secret used to get the token.  You can create a secret on the configure page
            of an Azure Active Directory Application
        resource (str, optional):
            The resource you are accessing.  Defaults to 'https://management.core.windows.net/'.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn', 'expiresOn', 'resource',
        'tokenType'.
    '''
    resource = resource or _DefaultValues.resource

    argument.validate_string_param(authority, 'authority')
    argument.validate_string_param(client_id, 'client_id')
    argument.validate_string_param(client_secret, 'client_secret')
    argument.validate_string_param(resource, 'resource')

    context = AuthenticationContext(authority, validate_authority)
    token_responses = []

    def callback(err, token_response):
        if err:
            raise Exception("Error:{} token_response:{}".format(err, token_response))
        token_responses.append(token_response)

    def token_func(context, extra=None):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource)
        context.token_request._get_token_with_client_credentials(client_secret, callback)

    context._acquire_token(callback, token_func)
    return token_responses[0]

def _acquire_token_with_authorization_code(
    authority,
    client_id,
    client_secret,
    authorization_code,
    redirect_uri,
    resource=None,
    validate_authority=True
):
    '''
    TODO: Verify the use of this method so we can complete testing before exposing

    Acquires a token when given an authorization code and other information.

    Args:
        authority (str):
            Your authority will have the form
            'https://login.windows.net/ABCDEFGH-1234-ABCD-1234-ABCDEFGHIJKL'.
            You must retrieve the this URI + GUID for your tenant.  You can find this on the Azure
            Active Directory Application Configure page and click view endpoints.  This string will
            be the root of the connection links given.
        client_id (str):
            The id of your client. Found on the configure page of Azure Active Directory
            Applications.
        client_secret (str):
            The client secret used to get the token.
        authorization_code (str):
            The authorization code used to get a token.
        redirect_uri (str):
            The URI to redirect to.
        resource (str, optional):
            The resource you are accessing.  Defaults to 'https://management.core.windows.net/'.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn',
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable',
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'.
    '''
    resource = resource or _DefaultValues.resource

    argument.validate_string_param(authority, 'authority')
    argument.validate_string_param(client_id, 'client_id')
    argument.validate_string_param(client_secret, 'client_secret')
    argument.validate_string_param(authorization_code, 'authorization_code')
    argument.validate_string_param(redirect_uri, 'redirect_uri')
    argument.validate_string_param(resource, 'resource')

    context = AuthenticationContext(authority, validate_authority)
    token_responses = []

    def callback(err, token_response):
        if err:
            raise Exception("Error:{} token_response:{}".format(err, token_response))
        token_responses.append(token_response)

    def token_func(context):
        context.token_request = TokenRequest(
            context._call_context, context, client_id, resource, redirect_uri
        )
        context.token_request._get_token_with_authorization_code(
            authorization_code, client_secret, callback
        )

    context._acquire_token(callback, token_func)
    return token_responses[0]

def acquire_token_with_refresh_token(
    authority,
    refresh_token,
    client_id=None,
    client_secret=None,
    resource=None,
    validate_authority=True
):
    '''
    Acquires a token when given a refresh token and other information.

    Args:
        authority (str):
            Your authority will have the form
            'https://login.windows.net/ABCDEFGH-1234-ABCD-1234-ABCDEFGHIJKL'.
            You must retrieve the this URI + GUID for your tenant.  You can find this on the Azure
            Active Directory Application Configure page and click view endpoints.  This string will
            be the root of the connection links given.
        refresh_token (str):
            The refresh token for the token you are refreshing.
        client_id (str, optional):
            The id of your client. For username password we use the XPlat Client Id by default.
        client_secret (str, optional):
            The client secret used to get the token.
        resource (str, optional):
            The resource you are accessing.  Defaults to 'https://management.core.windows.net/'.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn',
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable',
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'.
    '''
    client_id = client_id or _DefaultValues.client_id
    resource = resource or _DefaultValues.resource

    argument.validate_string_param(authority, 'authority')
    argument.validate_string_param(refresh_token, 'refresh_token')
    argument.validate_string_param(client_id, 'client_id')
    argument.validate_string_param(resource, 'resource')

    context = AuthenticationContext(authority, validate_authority)
    token_responses = []

    def callback(err, token_response):
        if err:
            raise Exception("Error:{} token_response:{}".format(err, token_response))
        token_responses.append(token_response)

    def token_func(context):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource)
        context.token_request.get_token_with_refresh_token(refresh_token, client_secret, callback)

    context._acquire_token(callback, token_func)
    return token_responses[0]

def _acquire_token_with_client_certificate(
    authority,
    client_id,
    certificate,
    thumbprint,
    resource=None,
    validate_authority=True
):
    '''
    TODO: Verify the use of this method so we can complete testing before exposing

    Acquires a token when given a client certificate and other information.

    Args:
        authority (str):
            Your authority will have the form
            'https://login.windows.net/ABCDEFGH-1234-ABCD-1234-ABCDEFGHIJKL'.
            You must retrieve the this URI + GUID for your tenant.  You can find this on the Azure
            Active Directory Application Configure page and click view endpoints.  This string will
            be the root of the connection links given.
        client_id (str):
            The id of your client. Found on the configure page of Azure Active Directory
            Applications.
        certificate (str):
            The certificate for the token you are getting.
        thumbprint (str):
            The thumbprint of the certificate.
        resource (str, optional):
            The resource you are accessing.  Defaults to 'https://management.core.windows.net/'.
        validate_authority (bool, optional):
            Indicates whether you want the authority validated. Defaults to True.

    Returns:
        dict: a dict with the following keys: 'accessToken', 'expiresIn',
        'expiresOn', 'familyName', 'givenName', 'isUserIdDisplayable',
        'refreshToken', 'resource', 'tenantId', 'tokenType', 'userId'
    '''
    resource = resource or _DefaultValues.resource

    argument.validate_string_param(authority, 'authority')
    argument.validate_string_param(client_id, 'client_id')
    argument.validate_string_param(certificate, 'certificate')
    argument.validate_string_param(thumbprint, 'thumbprint')
    argument.validate_string_param(resource, 'resource')

    context = AuthenticationContext(authority, validate_authority)
    token_responses = []

    def callback(err, token_response):
        if err:
            raise Exception("Error:{} token_response:{}".format(err, token_response))
        token_responses.append(token_response)

    def token_func(context):
        context.token_request = TokenRequest(context._call_context, context, client_id, resource)
        context.token_request.get_token_with_certificate(certificate, thumbprint, callback)

    context._acquire_token(callback, token_func)
    return token_responses[0]

class _DefaultValues:
    resource = 'https://management.core.windows.net/'

    # This client is common to all tenants.  It is used by the Azure XPlat tools and is used for
    # username password logins.
    client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
