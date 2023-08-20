# Visual Studio Team Services Authentication Library for Java (Preview) [![Build Status](https://travis-ci.org/Microsoft/vsts-authentication-library-for-java.svg?branch=master)](https://travis-ci.org/Microsoft/vsts-authentication-library-for-java)
Retrieve OAuth2 Access Token or Personal Access Tokens for Visual Studio Team Services (visualstudio.com) accounts.  Also provides secure storage for those secrets on different platforms.

To learn more about Visual Studio Team Services and our Java specific tools, please visit https://java.visualstudio.com.

What this library provides
--------------------------
This library provides:

1. a set of `authenticators` in the `core` module that can be used to retrieve credentials in the form of OAuth2 Access Token or Personal Access Token against any Visual Studio Team Services account.  
1. a set of secure `storage` providers that store retrieved secrets, as well as In memory and File system backed insecure storages.   
1. a set of `providers` that hide the interaction between `storage` and `authenticator`, and returns authenticated `client` that can be used directly against Visual Studio Team Services REST APIs.

### Available Secure Storage Providers:

| Secret Type | Windows (Credential Manager) | Linux (GNOME Keyring v2.22+)  | Mac OSX (Keychain)|
|--------------------------|------------------------|-------------------------|-------------------------|
| Username / Password Combo (`Credential`) | Yes | Yes | Yes |
| OAuth2 Access/Refresh Token (`TokenPair`) | Yes (On Windows 7, 8/8.1 and 10) | Yes | Yes | 
| VSTS Personal Access Token (`Token`) | Yes | Yes | Yes |


How to use this library
-----------------------

Maven is the preferred way to referencing this library.  

```xml
  <dependency>
    <groupId>com.microsoft.alm</groupId>
    <artifactId>auth-providers</artifactId>
    <version>0.6.4</version>
  </dependency>
```

If only interested in specific modules:

```xml
  <dependency>
    <groupId>com.microsoft.alm</groupId>
    <artifactId>auth-secure-storage</artifactId>
    <version>0.6.4</version>
  </dependency>
```

```xml
  <dependency>
    <groupId>com.microsoft.alm</groupId>
    <artifactId>auth-core</artifactId>
    <version>0.6.4</version>
  </dependency>
```

Here is a [Sample App](sample/src/main/java/com/microsoft/alm/auth/sample/App.java) that uses this library.


How to build
------------
1. Oracle JDK 6
1. Maven 3.2+
1. `mvn clean verify`


How can I contribute?
---------------------
This is a preview release, please open issues and give us feedback!  We also welcome Pull Requests.


License
-------
The MIT license can be found in [LICENSE.txt](LICENSE.txt)


Code of Conduct
---------------
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

