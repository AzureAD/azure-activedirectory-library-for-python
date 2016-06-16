# Microsoft Azure Active Directory Authentication Library (ADAL) for Python

<a href="https://pypi.python.org/pypi/adal/"><img src='https://pypip.in/d/adal/badge.svg'></a>

The ADAL for python library makes it easy for python applications to authenticate to AAD in order to access AAD protected web resources.

# Note
This is an early, pre-release version of the library.  It does not yet have support for any kind of caching.

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
From PowerShell, you can execute the following:

```powershell
### Install the Azure Resource Manager (ARM) PowerShell module from the PowerShell Gallery
Install-Module -Name AzureRm

### Install the AzureRm child modules (this may take a few minutes)
Install-AzureRm

### Authenticate to Microsoft Azure (an authentication dialog will open)
$null = Login-AzureRmAccount

### List out the Microsoft Azure subscriptions available to your account
Get-AzureRmSubscription | Format-Table -AutoSize

### Select the Microsoft Azure subscription you want to manipulate
Set-AzureRmContext -SubscriptionId ABCDEFGH-1234-1234-1234-ABCDEFGH

### List out the Azure Active Directory (AAD) Service Principals in your AAD tenant
Get-AzureRmADServicePrincipal | Sort-Object -Property DisplayName

### Assign the "contributor" role to your Azure Active Directory (AAD) Service Principal
New-AzureRmRoleAssignment -ServicePrincipalName http://PythonSDK -RoleDefinitionName Contributor
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

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## Contributing

All code is licensed under the MIT license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now.

## Quick Start

### Installation

``` $ pip install adal ```
