# Microsoft Azure Active Directory Authentication Library (ADAL) for Python

<a href="https://pypi.python.org/pypi/adal/"><img src='https://pypip.in/d/adal/badge.svg'></a>

The ADAL for python library makes it easy for python applications to authenticate to AAD in order to access AAD protected web resources.

## Usage

### Acquire Token with Client Credentials

In order to use this token acquisition method, you need to configure a service principal. Please follow [this walkthrough](https://azure.microsoft.com/en-us/documentation/articles/resource-group-create-service-principal-portal/).

See the [sample](./sample/client_credentials_sample.py).
```python
import adal

context = adal.AuthenticationContext('https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL')
RESOURCE = '00000002-0000-0000-c000-000000000000' #AAD graph resource
token = context.acquire_token_with_client_credentials(
    RESOURCE,
    "http://PythonSDK", 
    "Key-Configured-In-Portal")
```

### Acquire Token with client certificate
A service principal is also required. See the [sample](./sample/certificate_credentials_sample.py).
```python
import adal
context = adal.AuthenticationContext('https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL')
RESOURCE = '00000002-0000-0000-c000-000000000000' #AAD graph resource
token = context.acquire_token_with_client_certificate(
    RESOURCE,
    "http://PythonSDK",  
    'yourPrivateKeyFileContent', 
    'thumbprintOfPrivateKey')
```

### Acquire Token with Refresh Token
See the [sample](./sample/refresh_token_sample.py).
```python
import adal
context = adal.AuthenticationContext('https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL')
RESOURCE = '00000002-0000-0000-c000-000000000000' #AAD graph resource
token = context.acquire_token_with_username_password(
    RESOURCE, 
    'yourName',
    'yourPassword',
    'yourClientIdHere')

refresh_token = token['refreshToken']
token = context.acquire_token_with_refresh_token(
    refresh_token,
    'yourClientIdHere',
    RESOURCE)
```

### Acquire Token with device code
See the [sample](./sample/device_code_sample.py).
```python
context = adal.AuthenticationContext('https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL')
RESOURCE = '00000002-0000-0000-c000-000000000000' #AAD graph resource
code = context.acquire_user_code(RESOURCE, 'yourClientIdHere')
print(code['message'])
token = context.acquire_token_with_device_code(RESOURCE, code, 'yourClientIdHere')
``` 

### Acquire Token with authorization code
See the [sample](./sample/website_sample.py) for a complete bare bones web site that makes use of the code below.
```python
context = adal.AuthenticationContext('https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL')
RESOURCE = '00000002-0000-0000-c000-000000000000' #AAD graph resource
return auth_context.acquire_token_with_authorization_code(
            'yourCodeFromQueryString', 
            'yourWebRedirectUri', 
            RESOURCE, 
            'yourClientId', 
            'yourClientSecret')
``` 

## Samples and Documentation
[We provide a full suite of sample applications and documentation on GitHub](https://github.com/AzureADSamples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features.

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before.

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Contributing

All code is licensed under the MIT license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now.

## Quick Start

### Installation

``` $ pip install adal ```
