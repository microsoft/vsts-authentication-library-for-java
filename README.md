# Visual Studio Team Services Authentication Library for Java (Preview)
Retrieve OAuth2 Access Token or Personal Accesss Tokens for Visual Studio Team Services (visualstudio.com) accounts.  Also provides secure storage for those secrets on different platforms.

License
-------
The MIT license can be found in [LICENSE.txt](LICENSE.txt)

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
| OAuth2 Access/Refresh Token (`TokenPair`) | No | Yes | No | 
| VSTS Personal Access Token (`Token`) | Yes | Yes | Yes |


How to use this library
-----------------------
Please refer to the [Sample App](sample/src/main/java/com/microsoft/alm/auth/sample/App.java).


How to build
------------
1. Oracle JDK 6
1. Maven 3.2+
1. `mvn clean verify`


How can I contribute?
---------------------
We welcome Pull Requests.


Code of Conduct
---------------
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

