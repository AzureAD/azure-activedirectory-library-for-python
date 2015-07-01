'''
This is a sample config file.  Make a copy of it as config.py.  Then follow the provided
instructions to fill in your values.
'''
ACQUIRE_TOKEN_WITH_USERNAME_PASSWORD = {
    # Getting token with username and passwords is the simple method.  You need to create an Azure
    # Active Directory and a user.  Once you have done this, you can put the tenant name, username
    # and password combination here.
    #
    # Note: You need to attempt to login to the user at least once to create a non-temp password.
    #       To do this, go to http://manage.azure.com, sign in, create a new password, and use
    #       the password created here.

    "username" : "USERNAME@XXXXXXXX.onmicrosoft.com",
    "password" : None,
    "tenant" : "XXXXXXXX.onmicrosoft.com",

    "authorityHostUrl" : "https://login.windows.net",
}

ACQUIRE_TOKEN_WITH_CLIENT_CREDENTIALS = {
    # To use client credentials (Secret Key) you need to:
    # Create an Azure Active Directory (AD) instance on your Azure account
    # in this AD instance, create an application.  I call mine PythonSDK http://PythonSDK
    # Go to the configure tab and you can find all of the following information:

    # Click on 'View Endpoints' and Copy the 'Federation Metadata Document' entry.
    # The root + GUID URL is our authority.
    "authority" : "https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL",

    # Exit out of App Endpoints.  The client Id is on the configure page.
    "client_id" : "ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL",

    # In the keys section of the Azure AD App Configure page, create a key (1 or 2 years is fine)
    "secret" : "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a=",

    # NOTE: If this is to be used with ARM (the case of the Azure SDK) you will need to grant
    #       permissions to that service.  At this time Azure does not have this in the portal for
    #       Azure Resource Management.
    #       Here is an example using POSH (Powershell) Tools for Azure to grant those rights.
    #           Switch-AzureMode -Name AzureResourceManager
    #           Add-AzureAccount # This will pop up a login dialog
    #            # Look at the subscriptions returned and put one on the line below
    #           Select-AzureSubscription -SubscriptionId ABCDEFGH-1234-1234-1234-ABCDEFGH
    #           New-AzureRoleAssignment -ServicePrincipalName http://PythonSDK -RoleDefinitionName Contributor
}


# TODO: ADD DICTIONARIES FOR THE OTHER TESTS
# ACQUIRE_TOKEN_WITH_AUTHORIZATION_CODE
# ACQUIRE_TOKEN_WITH_REFRESH_TOKEN
# ACQUIRE_TOKEN_WITH_CLIENT_CERTIFICATE
