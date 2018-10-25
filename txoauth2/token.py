# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" The token endpoint. """

import string
import time
import json

from abc import ABCMeta, abstractmethod
from twisted.web.resource import Resource

from txoauth2.clients import PublicClient
from txoauth2.granttypes import GrantTypes
from .errors import InsecureConnectionError, MissingParameterError, InvalidParameterError, \
    InvalidTokenError, InvalidScopeError, UnsupportedGrantTypeError, OK, MultipleParameterError, \
    MultipleClientCredentialsError, OAuth2Error, InvalidClientIdError, DifferentRedirectUriError, \
    UnauthorizedClientError, MalformedParameterError, MultipleClientAuthenticationError, \
    NoClientAuthenticationError, MalformedRequestError


class TokenFactory(object):
    """ A factory that can generate tokens. """
    __metaclass__ = ABCMeta

    @abstractmethod
    def generateToken(self, lifetime, client, scope, additionalData=None):
        """
        Generate a new token. The generated token must comply to the specification
        (see https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/#token).
        See TokenResource::VALID_TOKEN_CHARS for a list of allowed characters in the token.
        :raises ValueError: If the scope is not valid.
        :param lifetime: The lifetime of the new token in seconds or None for infinite lifetime.
        :param client: The client that gets the new token.
        :param scope: A list of scopes that the new token will grant access to.
        :param additionalData: Any additional data that was passes to OAuth2::grantAccess.
        :return: A new token as a string.
        """
        raise NotImplementedError()


class TokenStorage(object):
    """ An object that stores and manages tokens. """
    __metaclass__ = ABCMeta

    @abstractmethod
    def contains(self, token):
        """
        :param token: The token to validate.
        :return: True if the token is stored in this token storage, False otherwise.
        """
        raise NotImplementedError()

    @abstractmethod
    def hasAccess(self, token, scope):
        """
        Return True if the token is stored in this token storage
        and grants access to the given list of scopes (e.g. was
        store called with the token and at least the give scopes).

        :raises KeyError: If the token is not in the token store.
        :param token: The token to validate.
        :param scope: The scopes the token must grant access to.
        :return: True, if the token grants access to the scopes, False otherwise.
        """
        raise NotImplementedError()

    @abstractmethod
    def getTokenAdditionalData(self, token):
        """
        Get the additional data that was passed to store together with the given token.

        :raises KeyError: If the token was not found in the token storage
        :param token: A token.
        :return: The additional data that was stored alongside the token.
        """
        raise NotImplementedError()

    @abstractmethod
    def getTokenScope(self, token):
        """
        Get the scope that was passed to store together with the given token.

        :raises KeyError: If the token was not found in the token storage
        :param token: A token.
        :return: The scope as a list of strings that was stored alongside the token.
        """
        raise NotImplementedError()

    @abstractmethod
    def getTokenClient(self, token):
        """
        Get the client id of the client that was passed to store together with the given token.

        :raises KeyError: If the token was not found in the token storage
        :param token: A token.
        :return: The id of the client that was stored alongside the token.
        """
        raise NotImplementedError()

    @abstractmethod
    def getTokenLifetime(self, token):
        """
        :raises KeyError: If the token was not found in the token storage
        :param token: A token.
        :return: The current lifetime of the given token in seconds.
        """
        raise NotImplementedError()

    @abstractmethod
    def store(self, token, client, scope, additionalData=None, expireTime=None):
        """
        Store the given token in the token storage alongside
        the optional additional data. If expireTime is not None,
        it marks the point in time in seconds since the epoch at
        which the token should expire
        (contains should then return False for this token).

        :raises ValueError: If the token is not a string.
        :param token: The token to store.
        :param client: The client that this token was made for.
        :param scope: The scope this token grants access to.
        :param additionalData: Optional additional data that
                               was passed to OAuth2.grantAccess.
        :param expireTime: Optionally the seconds since the epoch,
                           when the token should expire.
        """
        raise NotImplementedError()

    @abstractmethod
    def remove(self, token):
        """
        Remove the toke from the token storage.

        :raises KeyError: If the token was not found in the token storage
        :param token: The token to remove.
        """
        raise NotImplementedError()


class PersistentStorage(object):
    """
    A key value storage that can store data between a call to OAuth2.grantAccess
    and the corresponding POST request to the TokenResource from the client.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def put(self, key, data, expireTime=None):
        """
        Store the given data with the given key.
        If expireTime is not None, it marks when the data
        should expire in seconds since the epoch.

        :param key: The key of the data.
        :param data: Some data.
        :param expireTime: Optionally the seconds since the epoch,
                           when the data should expire.
        """
        raise NotImplementedError()

    @abstractmethod
    def pop(self, key):
        """
        Return the data that was previously stored with the given key and remove it.

        :raises KeyError: If no data was stored with the key.
        :param key: The key the data was stored at.
        :return: The data that was stored.
        """
        raise NotImplementedError()


class UserPasswordManager(object):
    """
    A password manager that can authenticate a resource owner with a username and password.
    This is only used in the Resource Owner Password Credentials Grant.
    See https://tools.ietf.org/html/rfc6749#section-4.3
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def authenticate(self, username, password):
        """
        Authenticate a resource owner.
        :param username: The username of the resource owner as a byte string.
        :param password: The plaintext password of the resource owner as a byte string.
        :return: True, if the resource owner could be authenticated, False otherwise.
        """
        raise NotImplementedError()


class TokenResource(Resource, object):
    """
    This resource handles creation and refreshing of access tokens.

    If authTokenLifeTime is None, the tokens generated by this resource will never expire.
    Otherwise, the generated access token will have a lifetime in seconds as specified by
    authTokenLifeTime. Additionally, a refresh token will be generated with an unlimited
    lifetime. This refresh token can be used at this resource to generate additional
    access tokens with limited lifetime, if the old one expired.

    There are two scenarios in which this resource plays a role:

    A: 1. The client's authorization request was granted by the user
          and a code was generated in OAuth2.grantAccess.
       2. The client now generates a POST request to this resource,
          passing the code as an argument.
       3. This resource creates and stores an access token and returns it.
          Depending on authTokenLifeTime, a refresh token is also created,
          stored and returned.

    B: 1. The client has a refresh token and an access token which expired.
       2. The client generates a POST request to this resource,
          passing the refresh token as an argument.
       3. This resource creates and stores another access token and returns it.
    """
    VALID_TOKEN_CHARS = string.digits + string.ascii_letters + '-._~+/'
    tokenFactory = None
    persistentStorage = None
    allowInsecureRequestDebug = False
    refreshTokenStorage = None
    # This is the token storage singleton
    _OAuthTokenStorage = None
    clientStorage = None
    authTokenLifeTime = 3600
    minRefreshTokenLifeTime = 1209600  # = 14 days
    defaultScope = None
    acceptedGrantTypes = [GrantTypes.RefreshToken.value, GrantTypes.AuthorizationCode.value,
                          GrantTypes.ClientCredentials.value, GrantTypes.Password.value]

    def __init__(self, tokenFactory, persistentStorage, refreshTokenStorage, authTokenStorage,
                 clientStorage, authTokenLifeTime=3600, minRefreshTokenLifeTime=1209600,
                 passwordManager=None, allowInsecureRequestDebug=False, grantTypes=None,
                 defaultScope=None):
        """
        Create a new TokenResource.
        The given authTokenStorage will be used to check tokens when
        isAuthorized or the oauth2 is used. The authTokenLifeTime
        parameter governs the lifetime of generated tokens in seconds.
        If it is None, refresh tokens will be generated in addition to
        the access tokens with limited lifetimes.

        :raises ValueError: If the password grant flow is enabled but no password manager supplied.
        :param tokenFactory: A token factory. Will generate both access and refresh tokens.
        :param persistentStorage: Persistent storage to access data stored by OAuth2.grantAccess.
        :param refreshTokenStorage: A token storage for refresh tokens.
        :param authTokenStorage: A token storage for access tokens. Will be used as a singleton.
        :param clientStorage: A handle to the storage of known clients.
        :param authTokenLifeTime: Either lifetime in seconds or None for an unlimited lifetime.
        :param minRefreshTokenLifeTime: Either the minimum lifetime of a refresh token in seconds
                                        or None for an unlimited lifetime.
        :param passwordManager: The password manager to use for the password grant flow.
        :param allowInsecureRequestDebug: If True, allow requests over insecure connections.
                                          Do NOT use in production!
        :param grantTypes: The grant types that are enabled for this authorization endpoint.
        :param defaultScope: The default scope for tokens if a request does not contain any.
        """
        super(TokenResource, self).__init__()
        self.allowedMethods = [b'POST']
        self.allowInsecureRequestDebug = allowInsecureRequestDebug
        self.refreshTokenStorage = refreshTokenStorage
        self.tokenFactory = tokenFactory
        self.persistentStorage = persistentStorage
        self.clientStorage = clientStorage
        self.passwordManager = passwordManager
        self.authTokenLifeTime = authTokenLifeTime
        self.minRefreshTokenLifeTime = minRefreshTokenLifeTime
        self.defaultScope = defaultScope
        TokenResource._OAuthTokenStorage = authTokenStorage
        if grantTypes is not None:
            if GrantTypes.Implicit in grantTypes:
                grantTypes.remove(GrantTypes.Implicit)
            grantTypes = [grantType.value if isinstance(grantType, GrantTypes) else grantType
                          for grantType in grantTypes]
            self.acceptedGrantTypes = grantTypes
        if GrantTypes.Password.value in self.acceptedGrantTypes and passwordManager is None:
            raise ValueError('The passwordManager must not be None '
                             'if the password grant flow is enabled')
        self.render_HEAD = None  # Disable automatic HEAD handling. pylint: disable=invalid-name

    def render_POST(self, request):  # pylint: disable=invalid-name
        """
        Handle a POST request according to the OAuth2 specification.
        See the docstring of this class for more information.

        :param request: The POST request.
        :return: A response or NOT_DONE_YET
        """
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError().generate(request)
        contentTypeHeader = request.getHeader(b'Content-Type')
        if contentTypeHeader is None or\
                not contentTypeHeader.startswith(b'application/x-www-form-urlencoded'):
            message = 'The Content-Type must be "application/x-www-form-urlencoded"'
            return MalformedRequestError(message).generate(request)
        if b'grant_type' not in request.args:
            return MissingParameterError(name='grant_type').generate(request)
        if len(request.args[b'grant_type']) != 1:
            return MultipleParameterError('grant_type').generate(request)
        try:
            grantType = request.args[b'grant_type'][0].decode('utf-8')
        except UnicodeDecodeError:
            return InvalidParameterError('grant_type').generate(request)
        if grantType not in self.acceptedGrantTypes:
            return UnsupportedGrantTypeError(grantType).generate(request)
        # noinspection PyTypeChecker
        if grantType not in [stdGrantType.value for stdGrantType in GrantTypes]:
            return self.onCustomGrantTypeRequest(request, grantType)
        client = self._authenticateClient(request)
        if isinstance(client, OAuth2Error):
            return client.generate(request)
        if grantType not in client.authorizedGrantTypes:
            return UnauthorizedClientError(grantType).generate(request)
        if grantType == GrantTypes.RefreshToken.value:
            return self._handleRefreshRequest(request, client)
        elif grantType == GrantTypes.AuthorizationCode.value:
            return self._handleAuthorizationCodeRequest(request, client)
        elif grantType == GrantTypes.ClientCredentials.value:
            return self._handleClientCredentialsRequest(request, client)
        elif grantType == GrantTypes.Password.value:
            return self._handlePasswordRequest(request, client)
        return UnsupportedGrantTypeError(grantType).generate(request)

    def _handleRefreshRequest(self, request, client):
        """
        Handle a request for the refresh token flow.

        :param request: The request.
        :param client: The client that makes the request.
        :return: The result of the request.
        """
        if b'refresh_token' not in request.args:
            return MissingParameterError('refresh_token').generate(request)
        if len(request.args[b'refresh_token']) != 1:
            return MultipleParameterError('refresh_token').generate(request)
        try:
            refreshToken = request.args[b'refresh_token'][0].decode('utf-8')
            tokenScope = self.refreshTokenStorage.getTokenScope(refreshToken)
            additionalData = self.refreshTokenStorage.getTokenAdditionalData(refreshToken)
            clientId = self.refreshTokenStorage.getTokenClient(refreshToken)
        except (KeyError, UnicodeDecodeError):
            return InvalidTokenError('refresh token').generate(request)
        if clientId != client.id:
            return InvalidTokenError('refresh token').generate(request)
        if b'scope' in request.args:
            if len(request.args[b'scope']) != 1:
                return MultipleParameterError('scope').generate(request)
            try:
                scope = request.args[b'scope'][0].decode('utf-8').split()
            except UnicodeDecodeError:
                return InvalidScopeError(request.args[b'scope'][0]).generate(request)
            for requestedScope in scope:
                if requestedScope not in tokenScope:
                    return InvalidScopeError(scope).generate(request)
        else:
            scope = tokenScope
        if not self.refreshTokenStorage.contains(refreshToken):
            return InvalidTokenError('refresh token').generate(request)
        try:
            accessToken = self._storeNewAccessToken(client, scope, additionalData)
        except ValueError:
            return InvalidScopeError(scope).generate(request)
        newRefreshToken = None
        if self._shouldExpireRefreshToken(refreshToken):
            self.refreshTokenStorage.remove(refreshToken)
            newRefreshToken = self._storeNewRefreshToken(client, scope, additionalData)
        return self._buildResponse(request, accessToken, scope, newRefreshToken)

    def _handleAuthorizationCodeRequest(self, request, client):
        """
        Handle a request for the authorization code flow.

        :param request: The request.
        :param client: The client that makes the request.
        :return: The result of the request.
        """
        redirectUri = None
        if b'code' not in request.args:
            return MissingParameterError('code').generate(request)
        if len(request.args[b'code']) != 1:
            return MultipleParameterError('code').generate(request)
        if b'redirect_uri' in request.args:
            if len(request.args[b'redirect_uri']) != 1:
                return MultipleParameterError('redirect_uri').generate(request)
            try:
                redirectUri = request.args[b'redirect_uri'][0].decode('utf-8')
            except UnicodeDecodeError:
                return InvalidParameterError('redirect_uri').generate(request)
        try:
            data = self.persistentStorage.pop('code' + request.args[b'code'][0].decode('utf-8'))
        except (KeyError, UnicodeDecodeError):
            return InvalidTokenError('authorization code').generate(request)
        if data['client_id'] != client.id:
            return InvalidTokenError('authorization code').generate(request)
        if data['redirect_uri'] is not None:
            if redirectUri is None:
                return MissingParameterError('redirect_uri').generate(request)
            if data['redirect_uri'] != redirectUri:
                return DifferentRedirectUriError().generate(request)
        additionalData = data['additional_data']
        scope = data['scope']
        accessToken = self._storeNewAccessToken(client, scope, additionalData)
        refreshToken = None
        if self.authTokenLifeTime is not None:
            refreshToken = self._storeNewRefreshToken(client, scope, additionalData)
        return self._buildResponse(request, accessToken, scope, refreshToken)

    def _handleClientCredentialsRequest(self, request, client):
        """
        Handle a request for the client credentials flow.

        :param request: The request.
        :param client: The client that makes the request.
        :return: The result of the request.
        """
        if isinstance(client, PublicClient):
            return UnauthorizedClientError(GrantTypes.ClientCredentials.value).generate(request)
        if b'scope' in request.args:
            if len(request.args[b'scope']) != 1:
                return MultipleParameterError('scope').generate(request)
            try:
                scope = request.args[b'scope'][0].decode('utf-8').split()
            except UnicodeDecodeError:
                return InvalidScopeError(request.args[b'scope'][0]).generate(request)
        else:
            if self.defaultScope is None:
                return MissingParameterError('scope').generate(request)
            scope = self.defaultScope
        try:
            accessToken = self._storeNewAccessToken(client, scope, None)
        except ValueError:
            return InvalidScopeError(scope).generate(request)
        return self._buildResponse(request, accessToken, scope)

    def _handlePasswordRequest(self, request, client):
        """
        Handle a request for the password flow.

        :param request: The request.
        :param client: The client that makes the request.
        :return: The result of the request.
        """
        for name in [b'username', b'password']:
            if name not in request.args:
                return MissingParameterError(name.decode('utf-8')).generate(request)
            if len(request.args[name]) != 1:
                return MultipleParameterError(name.decode('utf-8')).generate(request)
        username = request.args[b'username'][0]
        password = request.args[b'password'][0]
        if b'scope' in request.args:
            if len(request.args[b'scope']) != 1:
                return MultipleParameterError('scope').generate(request)
            try:
                scope = request.args[b'scope'][0].decode('utf-8').split()
            except UnicodeDecodeError:
                return InvalidScopeError(request.args[b'scope'][0]).generate(request)
        else:
            if self.defaultScope is None:
                return MissingParameterError('scope').generate(request)
            scope = self.defaultScope
        if not self.passwordManager.authenticate(username, password):
            return InvalidTokenError('username or password').generate(request)
        try:
            accessToken = self._storeNewAccessToken(client, scope, None)
        except ValueError:
            return InvalidScopeError(scope).generate(request)
        refreshToken = None
        if self.authTokenLifeTime is not None:
            refreshToken = self._storeNewRefreshToken(client, scope, None)
        return self._buildResponse(request, accessToken, scope, refreshToken)

    # noinspection PyMethodMayBeStatic
    # pylint: disable=no-self-use
    def onCustomGrantTypeRequest(self, request, grantType):
        """
        Gets called when a request with a custom grant type is encountered.
        It is up to this method to extract the client from the request and authenticate him.
        This method should get overwritten to handle the request.
        :param request: The request.
        :param grantType: The custom grant type.
        :return: The result of the POST request.
        """
        return UnsupportedGrantTypeError(grantType).generate(request)

    def _shouldExpireRefreshToken(self, refreshToken):
        """
        :param refreshToken: A valid refresh token.
        :return: Whether or not to expire the refresh token.
        """
        tokenLifetime = self.refreshTokenStorage.getTokenLifetime(refreshToken)
        return tokenLifetime >= self.minRefreshTokenLifeTime

    def _storeNewRefreshToken(self, client, scope, additionalData):
        """
        Create and store a new refresh token.
        :raises ValueError: If the scope is invalid.
        :param client: The client the refresh token belongs to.
        :param scope: The scope of the refresh token.
        :param additionalData: Additional data of the refresh token.
        :return: The new refresh token.
        """
        refreshToken = self.tokenFactory.generateToken(
            None, client, scope=scope, additionalData=additionalData)
        if not self.isValidToken(refreshToken):
            raise ValueError('Generated token is invalid: {token}'
                             .format(token=refreshToken))
        self.refreshTokenStorage.store(refreshToken, client, scope=scope,
                                       additionalData=additionalData)
        return refreshToken

    def _storeNewAccessToken(self, client, scope, additionalData):
        """
        Create and store a new access token.
        :raises ValueError: If the scope is invalid.
        :param client: The client the access token belongs to.
        :param scope: The scope of the access token.
        :param additionalData: Additional data of the access token.
        :return: The new access token.
        """
        accessToken = self.tokenFactory.generateToken(
            self.authTokenLifeTime, client, scope=scope, additionalData=additionalData)
        if not self.isValidToken(accessToken):
            raise ValueError('Generated token is invalid: {token}'.format(token=accessToken))
        expireTime = None
        if self.authTokenLifeTime is not None:
            expireTime = time.time() + self.authTokenLifeTime
        self.getTokenStorageSingleton().store(
            accessToken, client, scope=scope,
            additionalData=additionalData, expireTime=expireTime)
        return accessToken

    def _buildResponse(self, request, accessToken, scope, refreshToken=None):
        """
        Helper method for render_POST to generate a response
        with an access token and an optional refresh token.

        :param request: The POST request.
        :param accessToken: The access token to send back.
        :param scope: The scope of the access token to send back.
        :param refreshToken: An optional refresh token to send back.
        :return: A response as as a json string.
        """
        result = {
            'access_token': accessToken,
            'token_type': 'Bearer',
            'scope': ' '.join(scope)
        }
        if self.authTokenLifeTime is not None:
            result['expires_in'] = int(self.authTokenLifeTime)
        if refreshToken is not None:
            result['refresh_token'] = refreshToken
        request.setHeader('Content-Type', 'application/json;charset=UTF-8')
        request.setHeader('Cache-Control', 'no-store')
        request.setHeader('Pragma', 'no-cache')
        request.setResponseCode(OK)
        return json.dumps(result).encode('utf-8')

    def _authenticateClient(self, request):
        """
        Identify and authenticate a client by the credentials in the request.
        :param request: The request.
        :return: The authenticated client or an OAuth2Error.
        """
        clientCredentials = self._getClientCredentials(request)
        if isinstance(clientCredentials, OAuth2Error):
            return clientCredentials
        clientId, secret = clientCredentials
        if clientId is None:
            return NoClientAuthenticationError()
        try:
            clientId = clientId.decode('utf-8')
        except UnicodeDecodeError:
            return MalformedParameterError('client_id')
        if secret is not None:
            try:
                secret = secret.decode('utf-8')
            except UnicodeDecodeError:
                return MalformedParameterError('client_secret')
        try:
            client = self.clientStorage.getClient(clientId)
        except KeyError:
            return InvalidClientIdError()
        if isinstance(client, PublicClient):
            return client
        return self.clientStorage.authenticateClient(client, request, secret)

    @staticmethod
    def _getClientCredentials(request):
        """
        Parse the client id and secret from the request, if the request contains them.
        :param request: The request that may contain client credentials.
        :return: An OAuth2Error or an optional user id and an optional client secret.
        """
        clientId = None
        secret = None
        authorizationHeader = request.getHeader(b'Authorization')
        if authorizationHeader is not None and\
                authorizationHeader.strip().lower().startswith(b'basic'):
            clientId = request.getUser()
            clientId = None if clientId == '' else clientId
            if clientId is not None:
                secret = request.getPassword()
                secret = None if secret == '' else secret
        if b'client_id' in request.args:
            if len(request.args[b'client_id']) != 1:
                return MultipleClientCredentialsError()
            if clientId is not None and clientId != request.args[b'client_id'][0]:
                return MultipleClientCredentialsError()
            clientId = request.args[b'client_id'][0]
        if b'client_secret' in request.args:
            if secret is not None:
                return MultipleClientAuthenticationError()
            if len(request.args[b'client_secret']) != 1:
                return MultipleParameterError('client_secret')
            secret = request.args[b'client_secret'][0]
        return clientId, secret

    @classmethod
    def isValidToken(cls, token):
        """
        Check if a token conforms tho the OAuth2 specification.
        See https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/#token

        :param token: The token to check.
        :return: True, if the token conforms to the specification, False otherwise
        """
        return all(char in cls.VALID_TOKEN_CHARS for char in token)

    @staticmethod
    def getTokenStorageSingleton():
        """
        Access the static access token storage singleton.
        The singleton must have been previously initialized
        by instantiating a TokenResource.

        :return: The access token storage.
        """
        if TokenResource._OAuthTokenStorage is None:
            raise ValueError('The access token storage is not initialized')
        return TokenResource._OAuthTokenStorage
