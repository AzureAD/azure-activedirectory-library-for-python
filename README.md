# Microsoft Azure Active Directory Authentication Library (ADAL) for Python
=====================================

|[Getting Started](https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki)| [Docs](https://aka.ms/aaddev)| [Samples](https://github.com/azure-samples?query=active-directory)| [Support](README.md#community-help-and-support)
| --- | --- | --- | --- |


The ADAL for Python library enables python applications to authenticate with Azure AD and get tokens to access Azure AD protected web resources.

You can learn in detail about ADAL Python functionality and usage documented in the [Wiki](https://github.com/AzureAD/azure-activedirectory-library-for-python/wiki).

## Versions
Current version - 0.6.0

Minimum recommended version - 0.6.0

You can find the changes for each version under [Releases](https://github.com/AzureAD/azure-activedirectory-library-for-python/releases).

> Note: Changes on 'client_id' and 'resource' arguments after 0.1.0
>
>The convenient methods in 0.1.0 have been removed, and now your application should provide parameter values to `client_id` and `resource`.
>
>2 Reasons:
>
>* Each adal client should have an Application ID representing a valid application registered in a tenant. The old methods borrowed the client-id of [azure-cli](https://github.com/Azure/azure-xplat-cli), which is never right. It is simple to register your application and get a client id. You can follow [this article](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications).
>
>* The old method defaults the `resource` argument to 'https://management.core.windows.net/', now you can just supply this value explictly. Please note, there are lots of different azure resources you can acquire tokens through adal though, for example, the samples in the repository acquire for the 'graph' resource. Because it is not an appropriate assumption to be made at the library level, we removed the old defaults.


## Samples and Documentation
We provide a full suite of [sample applications on GitHub](https://github.com/azure-samples?utf8=%E2%9C%93&q=active-directory&type=&language=) to help you get started with learning the Azure Identity system. This includes tutorials for native clients and web applications. We also provide full walkthroughs for authentication flows such as OAuth2, OpenID Connect and for calling APIs such as the Graph API.

You can find the relevant samples by scenarios listed in this [document](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-code-samples) as well as [inside this library repo](https://github.com/AzureAD/azure-activedirectory-library-for-python/tree/dev/sample).

The documents on [Auth Scenarios](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-authentication-scenarios#application-types-and-scenarios) and [Auth protocols](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code) are recommended reading.

## Community Help and Support

We leverage [Stack Overflow](http://stackoverflow.com/) to work with the community on supporting Azure Active Directory and its SDKs, including this one! We highly recommend you ask your questions on Stack Overflow (we're all on there!) Also browser existing issues to see if someone has had your question before.

We recommend you use the "adal" tag so we can see it! Here is the latest Q&A on Stack Overflow for ADAL: [http://stackoverflow.com/questions/tagged/adal](http://stackoverflow.com/questions/tagged/adal)

## Security Reporting

If you find a security issue with our libraries or services please report it to [secure@microsoft.com](mailto:secure@microsoft.com) with as much detail as possible. Your submission may be eligible for a bounty through the [Microsoft Bounty](http://aka.ms/bugbounty) program. Please do not post security issues to GitHub Issues or any other public site. We will contact you shortly upon receiving the information. We encourage you to get notifications of when security incidents occur by visiting [this page](https://technet.microsoft.com/en-us/security/dd252948) and subscribing to Security Advisory Alerts.

## Contributing

All code is licensed under the MIT license and we triage actively on GitHub. We enthusiastically welcome contributions and feedback. Please read the [contributing guide](./contributing.md) before starting.

## We Value and Adhere to the Microsoft Open Source Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
