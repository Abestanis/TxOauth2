# TxOAuth2 [![Build Status](https://github.com/Abestanis/TxOauth2/workflows/Tests/badge.svg)](https://github.com/Abestanis/TxOauth2/actions) [![codecov](https://codecov.io/gh/Abestanis/TxOauth2/branch/master/graph/badge.svg)](https://codecov.io/gh/Abestanis/TxOauth2)
This Python module helps to implement an OAuth2 Endpoint in Twisted and provides mechanism to protect resources with OAuth2 authentication.

## Usage

A sample usage can be found in the [example folder](https://github.com/Abestanis/TxOauth2/blob/master/example/main.py).


You will need to create a [TokenResource](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/token.py#L192) 
and an OAuth2 endpoint by subclassing the [OAuth2 class](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/resource.py#L39)
and insert them somewhere into your server hierarchy (e.g. add both at the same place by using
```python
root.putChild(b"oauth2", OAuth2Subclass.initFromTokenResource(tokenResource, subPath=b"token"))
```
see [the example](https://github.com/Abestanis/TxOauth2/blob/master/example/main.py#L128)).

Depending on which OAuth2 grant flows you want to support, you may not need both resources.
The [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-1.3.2) only needs the OAuth2 endpoint, 
the [Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-1.3.1) needs both and the others only need the TokenResource.
See the [specification](https://tools.ietf.org/html/rfc6749#section-1.3) for an indepth explanation of the grant flows.
You can enable the flows by adding the [GrantType](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/granttypes.py) 
to the list passed as the ```grantType``` Parameter to the OAuth2 and TokenResource endpoints.
It is best to only enable as few grant types as possible.

The [Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-1.3.1) flow is the most commonly used, but it is also the most complicated to implement:
The OAuth2 subclass will need to overwrite the [onAuthenticate](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/resource.py#L242) method.
This method will be called, when a [User](#terminology) is redirected to your server by a [Client](#terminology) to authorize access to some [scope](#terminology) by the client.
Within the method, you should serve or redirect to a page that allows the user to authorize the client.
See [here](https://www.oauth.com/oauth2-servers/scope/user-interface/) to get an idea of how such a page could look like.
If the user approves the authorization, you need to call [grantAccess](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/resource.py#L308)
or [denyAccess](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/resource.py#L277) if the user denies.

To protect your resources you need to either use the [oauth](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/authorization.py#L92)
decorator on the ```render_*``` methods of your resources or check the result of [isAuthorized](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/authorization.py#L47)
as demonstrated [here](https://github.com/Abestanis/TxOauth2/blob/master/example/main.py#L39).

Finally you need to register the [Clients](#terminology) by storing them in your implementation of 
the [ClientStorage](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/clients.py#L17).

This module does not deal with token storage, creation and validation, client storage, persistent storage or user password management.
Depending on the enabled grant types you will need to implement a 
[TokenFactory](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/token.py#L21),
[TokenStorage](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/token.py#L41),
[PersistentStorage](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/token.py#L140),
[ClientStorage](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/clients.py#L17) and 
[UserPasswordManager](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/token.py#L173).
A few implementations of these interfaces can be found in the [imp package](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/imp.py).
You may also use the tests in the ````tests```` directory to verify the expected behaviour of your implementation.

## Installation

Run ```pip install txoauth2``` or download the wheel from [PyPI](https://pypi.org/project/txoauth2/) or [Github](https://github.com/Abestanis/TxOauth2/releases).

## Terminology

* __User__: A user, also called the resource owner, is the actual owner of a resource and he can grant access to the resource to a client. It is up to you to identify and authenticate a user. You can pass additionalData to ```grantAccess``` that identifies an user. This additional data will be passed to the token generator and storage, which allows for the user information to be encoded into the token.
* __Client__: A client is an other application that wants to access a protected resource that is owned by the user. The client has no rights if they have not been explicitly granted by the user. Clients are represented by subclasses of the [Client class](https://github.com/Abestanis/TxOauth2/blob/master/txoauth2/clients.py#L53).
* __Token__: There are two types of tokens: Access Tokens and Refresh Tokens. Access Tokens allow access to a protected resource. If they expire, the client can use the Refresh Token to generate a new Access Token. [A token can only contain alphanumeric and the following characters](https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/#token): ```-._~+/```
* __Scope__: A scope identifies a range collection of resources that a client can request access to. The meaning of individual scope names are not fixed and it is up to the server maintainer to define the scopes known to the server and their meaning.

## Security

The OAuth2 specification requires that the protected resource and the OAuth2 endpoint is served via a secure connection (e.g. https).
To allow insecure connections for local testing, pass ```allowInsecureRequestDebug=True``` where it is accepted.
__Do not do this__ in your real server because everybody will be able to read the tokens and use them to access the protected resources!
