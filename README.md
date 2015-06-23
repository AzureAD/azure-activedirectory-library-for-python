# Microsoft Azure Active Directory Authentication Library (ADAL) for Python

[![Code Issues](http://www.quantifiedcode.com/api/v1/project/4b429ad7e2e54d7a8393cc0e49930b10/badge.svg)](http://www.quantifiedcode.com/app/project/4b429ad7e2e54d7a8393cc0e49930b10)


<a href="https://pypi.python.org/pypi/adal/"><img src='https://pypip.in/d/adal/badge.svg'></a>

The ADAL for python library makes it easy for python applications to authenticate to AAD in order to access AAD protected web resources.

## Usage

### Acquire Token with Username & Password

```python
import adal
token_response = adal.acquire_token_with_username_password(
	'https://login.windows.net/ACTIVE_DIRECTORY_TENANT.onmicrosoft.com', 
	'username@ACTIVE_DIRECTORY_TENANT.onmicrosoft.com', 
	'password'
)
```

### Acquire Token with Client Credentials

In order to use this token acquisition method, you need to:

1) Create an Azure Active Directory (AD) instance on your Azure account

2) Create an application in the AD instance and name it PythonSDK http://PythonSDK

3) Go to the configure tab and you can find all of the following information:

- Click on 'View Endpoints' and Copy the 'Federation Metadata Document' entry. The Root + GUID URL is our Authority.
- Exit out of App Endpoints.  The Client ID is on the configure page.
- In the keys section of the Azure AD App Configure page, create a key (1 or 2 years is fine)


```python
import adal
token_response = adal.acquire_token_with_client_credentials(
    "https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL", # Authority
    "ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL", # Client ID
    "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a=" # Client Secret
)
```

If you are using this with the Azure SDK, you will need to give the PythonSDK application we have access.
From powershell you can execute the following:

```
Switch-AzureMode -Name AzureResourceManager
Add-AzureAccount # This will pop up a login dialog
# Look at the subscriptions returned and put one on the line below
Select-AzureSubscription -SubscriptionId ABCDEFGH-1234-1234-1234-ABCDEFGH
New-AzureRoleAssignment -ServicePrincipalName http://PythonSDK -RoleDefinitionName Contributor
```

### Acquire Token with Refresh Token

```python
import adal
token_response = adal.acquire_token_with_username_password(
	'https://login.windows.net/ACTIVE_DIRECTORY_TENANT.onmicrosoft.com', 
	'username@ACTIVE_DIRECTORY_TENANT.onmicrosoft.com', 
	'password'

# Use returned refresh token to acquire a new token.
refresh_token = token_response['refreshToken']
token_response = adal.acquire_token_with_refresh_token(authority, refresh_token)
```

## Samples and Documentation
[We provide a full suite of sample applications and documentation on GitHub](https://github.com/AzureADSamples) to help you get started with learning the Azure Identity system. This includes tutorials for native clients such as Windows, Windows Phone, iOS, OSX, Android, and Linux. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect, Graph API, and other awesome features. 

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before. 

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Contributing

All code is licensed under the Apache 2.0 license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now. 

## Quick Start

### Installation

``` $ pip install adal ```
