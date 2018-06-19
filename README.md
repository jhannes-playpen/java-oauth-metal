# Getting started with OAuth2 bare metal for Java

### Prerequisites

* Google (gmail) account if you want to test out the Google OAuth2 scenario

Very brief guide:

1. Create a local `application.properties` file based on `application.properties.template`
2. Register a Google API application in the
   [Google API Console](https://console.cloud.google.com/apis/credentials)
   and place the `google.client.id` and `google.client.secret` in `application.properties`
3. Register a Azure AD Application at
   [Application Registration Portal](https://apps.dev.microsoft.com/)
   and place the `ad.client.id` and `ad.client.secret` in `application.properties`
4. Start the main class

## Enterprise Active Directory Applications

A good way of creating access controlled applications is to use an Enterprise
Application in Azure Active Directory. This allows application role assignments
to individual users and users in specified Active Directory group. It also
gives the option for security features such as MFA (multi-factor authorization)
and auditing.

Setting up an Active Directory Enterprise Application:

1. Log into [Azure Portal](https://portal.azure.com). You may have to create a trial account.
2. If you don't have access to your organization's Active Directory, you
   can [create your own AD for testing purpose](https://portal.azure.com/#create/Microsoft.AzureActiveDirectory)
3. Use your [AD's Directory ID](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties)
   as `enterprise.tenant` in `application.properties`
4. Create an [Application Registration](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).
   Use the Application ID as `enterprise.client.id` in `application.properties`
5. In your Application Registration, select Settings and Reply URLs. Add
   `http://localhost:9080/enterprise/oauth2/callback` (additional URLs are required for deployment)
6. In your Application Registration, select Settings and Keys. Create a
   key and store it as `enterprise.client.secret` in `application.properties`
7. In you Application Registration, select Manifest. You have to add `appRoles` as
   per [Azure Multitenant Documentation](https://docs.microsoft.com/en-us/azure/architecture/multitenant-identity/app-roles).
   You also have to set `"groupMembershipClaims": "SecurityGroup"`
8. Click the link under "Managed application in local directory" to go to the
   enterprise application configuration.
9. Under "Users and groups", add a user that can test the application and 
   assign the user to one of the roles created under step 8.

Make sure you have updated `application.properties` with `enterprise.tenant`,
`enterprise.client.id` and `enterprise.client.secret`. Start the Application
main class and point a web browser to http://localhost:9080.

You can test the setup under Enterprise application login. The decoded
ID token should contain the Application Role assigned to the user who
logs in.

### Understanding the Oauth2 code flow

![UML Sequence Diagram of Oauth2 flow](http://www.plantuml.com/plantuml/proxy?src=https://github.com/jhannes-playpen/java-oauth-metal/master/doc/oauth2-sequence.puml)


## Security controls

There are a number of security controls that can be set up for an Enterprise application:

* Under "Properties", turn "User assignment required" on to restrict unassigned users
  from even getting an access token for the application.
* Under "Users and groups", users and groups can be assigned to the applicaton and
  to specific application roles
* "Self-service" is a feature I haven't examined yet, but it seems to be a feature
  for users to request access to the application
* "Conditional access" (requires premium AD) allows you to specify that users must use
  Multi-factor authentication (MFA, also known as two-factor) or that they can
  only access the application from certain geographical locations or IP addresses
* "Sign-ins" and "Audit logs" allows an admin to see logins and other security critical
  events


### Open questions

* What requirements are there for users to create an application in their own Active Directory?
* Automatic enrollment with https://docs.microsoft.com/en-us/azure/architecture/multitenant-identity/run-the-app
* Can the "master application" read access logs from tenants?
