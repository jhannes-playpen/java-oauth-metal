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
