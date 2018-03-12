# Microsoft Azure Active Directory Authentication Library (ADAL) for Python

The ADAL for python library makes it easy for python applications to authenticate to AAD in order to access AAD protected web resources.

## Usage

### Install

To support 'service principal' with certificate, ADAL depends on the 'cryptography' package. For smooth installation, some suggestions:

* For Windows and macOS

  Upgrade to the latest pip (8.1.2 as of June 2016) and just do `pip install adal`.

* For Linux

  Upgrade to the latest pip (8.1.2 as of June 2016).

  You'll need a C compiler, libffi + its development headers, and openssl + its development headers.
  Refer to [cryptography installation](https://cryptography.io/en/latest/installation/)

* To install from source:

  Upgrade to the latest pip (8.1.2 as of June 2016).
  To avoid dealing with compilation errors from cryptography, first run `pip install cryptography` to use statically-linked wheels.
  Next, run `python setup.py install`

  If you still like to build from source, refer to [cryptography installation](https://cryptography.io/en/latest/installation/).
  For more context, start with this [stackoverflow thread](http://stackoverflow.com/questions/22073516/failed-to-install-python-cryptography-package-with-pip-and-setup-py).

### Acquire Token with Client Credentials

In order to use this token acquisition method, you need to configure a service principal. Please follow [this walkthrough](https://azure.microsoft.com/en-us/documentation/articles/resource-group-create-service-principal-portal/).

Find the `Main logic` part in the [sample](sample/client_credentials_sample.py#L46-L55).

### Acquire Token with client certificate
A service principal is also required.
Find the `Main logic` part in the [sample](sample/certificate_credentials_sample.py#L55-L64).

### Acquire Token with Refresh Token
Find the `Main logic` part in the [sample](sample/refresh_token_sample.py#L47-L69).

### Acquire Token with device code
Find the `Main logic` part in the [sample](sample/device_code_sample.py#L49-L54).

### Acquire Token with authorization code
Find the `Main logic` part in the [sample](sample/website_sample.py#L107-L115) for a complete bare bones web site that makes use of the code below.

## Logging

#### Personal Identifiable Information (PII) & Organizational Identifiable Information (OII)

Starting from ADAL Python 0.5.1, by default, ADAL logging does not capture or log any PII or OII.  The library allows app developers to turn this on by configuring the `enable_pii` flag on the AuthenticationContext. By turning on PII or OII, the app takes responsibility for safely handling highly-sensitive data and complying with any regulatory requirements.

```python
//PII or OII logging disabled. Default Logger does not capture any PII or OII.
auth_context = AuthenticationContext(...)

//PII or OII logging enabled
auth_context = AuthenticationContext(..., enable_pii=True)
```

## Samples and Documentation
We provide a full suite of [sample applications on GitHub](https://github.com/azure-samples?utf8=%E2%9C%93&q=active-directory&type=&language=) and an [Azure AD developer landing page](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-developers-guide) to help you get started with learning the Azure Identity system. This includes tutorials for native clients and web applications. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect and for calling APIs such as the Graph API.

It is recommended to read the [Auth Scenarios](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-authentication-scenarios) doc, specifically the [Scenarios section](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-authentication-scenarios#application-types-and-scenarios).  For some topics about registering/integrating an app, checkout [this doc](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications).  And finally, we have a great topic on the Auth protocols you would be using and how they play with Azure AD in [this doc](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code).

While Python-specific samples will be added into the aforementioned documents as an on-going effort, you can always find [most relevant samples just inside this library repo](https://github.com/AzureAD/azure-activedirectory-library-for-python/tree/dev/sample).

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before.

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## Contributing

All code is licensed under the MIT license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. You can clone the repo and start contributing now.

## We Value and Adhere to the Microsoft Open Source Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Quick Start

### Installation

``` $ pip install adal ```

### http tracing/proxy
If you need to bypass self-signed certificates, turn on the environment variable of `ADAL_PYTHON_SSL_NO_VERIFY`


## Note

### Changes on 'client_id' and 'resource' arguments after 0.1.0
The convenient methods in 0.1.0 have been removed, and now your application should provide parameter values to `client_id` and `resource`.

2 Reasons:

* Each adal client should have an Application ID representing a valid application registered in a tenant. The old methods borrowed the client-id of [azure-cli](https://github.com/Azure/azure-xplat-cli), which is never right. It is simple to register your application and get a client id. You can follow [this walkthrough](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications). Do check out if you are new to AAD.

* The old method defaults the `resource` argument to 'https://management.core.windows.net/', now you can just supply this value explictly. Please note, there are lots of different azure resources you can acquire tokens through adal though, for example, the samples in the repository acquire for the 'graph' resource. Because it is not an appropriate assumption to be made at the library level, we removed the old defaults.
