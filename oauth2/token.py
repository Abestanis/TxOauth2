# Copyright (c) Sebastian Scholz
# See LICENSE for details.
import string
import time
from twisted.web.resource import Resource, NoResource
import json

from .errors import InsecureConnectionError, MissingParameterError, \
    InvalidParameterError, InvalidTokenError, InvalidScopeError


class TokenFactory(object):
    """
    A factory that can generate tokens.
    """
    def generateToken(self, lifetime, client, scope, additionalData=None):
        """
        Generate a new token. The generated token must comply to the specification
        (see https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/#token).
        See TokenResource::VALID_TOKEN_CHARS for a list of allowed characters in the token.
        :param lifetime: The lifetime of the new token in seconds or None for infinite lifetime.
        :param client: The client that gets the new token.
        :param scope: A list of scopes that the new token will grant access to.
        :param additionalData: Any additional data that was passes to OAuth2::grantAccess.
        :return: A new token as a string.
        """
        raise NotImplementedError()


class TokenStorage(object):
    """
    An object that stores and manages tokens.
    """
    def contains(self, token, scope):
        """
        Return True if the token is stored in this token storage
        and grants access to the given list of scopes (e.g. was
        store called with the token and at least the give scopes).

        :param token: The token to validate
        :param scope: The scopes the token must grant access to.
        :return: True, if the token grants access to the scopes, False otherwise.
        """
        raise NotImplementedError()

    def getTokenData(self, token):
        """
        Get the additional data that was passed to
        store together with the given token.

        :param token: A token.
        :return: The additional data that was stored alongside the token.
        :raises: KeyError, if the token was not found in the token storage
        """
        raise NotImplementedError()

    def store(self, token, client, scope, additionalData=None, expireTime=None):
        """
        Store the given token in the token storage alongside
        the optional additional data. If expireTime is not None,
        it marks the point in time in seconds since the epoch at
        which the token should expire
        (contains should then return False for this token).

        :param token: The token to store.
        :param client: The client that this token was made for.
        :param scope: The scope this token grants access to.
        :param additionalData: Optional additional data that
                               was passed to OAuth2.grantAccess.
        :param expireTime: Optionally the seconds since the epoch,
                           when the token should expire.
        """
        raise NotImplementedError()


class PersistentStorage(object):
    """
    A key value storage that can store data between a call to OAuth2.grantAccess
    and the corresponding POST request to the TokenResource from the client.
    """
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

    def get(self, key):
        """
        Return the data that was previously stored with the given key.

        :param key: The key the data was stored at.
        :return: The data that was stored.
        :raises: KeyError, if no data was stored at the key.
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
    VALID_TOKEN_CHARS = string.digits + string.ascii_letters + '-.~+/'
    tokenFactory = None
    persistentStorage = None
    allowInsecureRequestDebug = False
    refreshTokenStorage = None
    # This is the token storage singleton
    _OAuthTokenStorage = None
    clientStorage = None
    authTokenLifeTime = 3600

    def __init__(self, tokenFactory, persistentStorage, refreshTokenStorage, authTokenStorage,
                 clientStorage, authTokenLifeTime=3600, allowInsecureRequestDebug=False):
        """
        Create a new TokenResource.
        The given authTokenStorage will be used to check tokens when
        isAuthorized or the oauth2 is used. The authTokenLifeTime
        parameter governs the lifetime of generated tokens in seconds.
        If it is None, refresh tokens will be generated in addition to
        the access tokens with limited lifetimes.

        :param tokenFactory: A token factory. Will generate both access and refresh tokens.
        :param persistentStorage: Persistent storage to access data stored by OAuth2.grantAccess.
        :param refreshTokenStorage: A token storage for refresh tokens.
        :param authTokenStorage: A token storage for access tokens. Will be used as a singleton.
        :param clientStorage: A handle to the storage of known clients.
        :param authTokenLifeTime: Either lifetime in seconds or None for an unlimited lifetime.
        :param allowInsecureRequestDebug: If True, allow requests over insecure connections.
                                          Do NOT use in production!
        """
        super(TokenResource, self).__init__()
        self.allowedMethods = ['POST']
        self.allowInsecureRequestDebug = allowInsecureRequestDebug
        self.refreshTokenStorage = refreshTokenStorage
        self.tokenFactory = tokenFactory
        self.persistentStorage = persistentStorage
        self.clientStorage = clientStorage
        self.authTokenLifeTime = authTokenLifeTime
        TokenResource._OAuthTokenStorage = authTokenStorage

    def render_POST(self, request):
        """
        Handle a POST request according to the OAuth2 specification.
        See the docstring of this class for more information.

        :param request: The POST request.
        :return: A response or NOT_DONE_YET
        """
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError().generate(request)
        if b'grant_type' not in request.args:
            return MissingParameterError(name='grant_type')
        if request.args[b'grant_type'][0] == b'refresh_token':
            for argument in [b'client_id', b'client_secret', b'refresh_token']:
                if argument not in request.args:
                    return MissingParameterError(name=argument).generate(request)
            try: # TODO: Support client id and secret in HTTP Authentication
                client = self.clientStorage.getClient(request.args[b'client_id'][0])
            except KeyError:
                return InvalidParameterError('client_id').generate(request)
            if client.clientSecret != request.args[b'client_secret'][0]:
                return InvalidParameterError('client_secret').generate(request)
            refreshToken = request.args[b'refresh_token'][0]
            try:
                scope, additionalData = self.refreshTokenStorage.getTokenData(refreshToken)
            except KeyError:
                return InvalidTokenError('refresh token').generate(request)
            if b'scope' in request.args:
                if scope != request.args[b'scope'][0]: # TODO: Support multiple scopes
                    return InvalidScopeError(request.args[b'scope'][0]).generate(request)
                scope = request.args[b'scope'][0]
            if not self.refreshTokenStorage.contains(refreshToken, scope):
                return InvalidTokenError('refresh token').generate(request)
            accessToken = self.tokenFactory.generateToken(
                self.authTokenLifeTime, client, scope=scope, additionalData=additionalData)
            if not self.isValidToken(accessToken):
                raise ValueError('Generated token is invalid: {token}'.format(token=accessToken))
            expireTime = None
            if self.authTokenLifeTime is not None:
                expireTime = int(time.time()) + self.authTokenLifeTime
            self.getTokenStorageSingleton().store(
                accessToken, client, scope=scope,
                additionalData=additionalData, expireTime=expireTime)
            return self.buildResponse(request, accessToken)
        elif request.args[b'grant_type'][0] == b'authorization_code':
            for argument in [b'client_id', b'client_secret', b'code', b'redirect_uri']:
                if argument not in request.args:
                    return MissingParameterError(name=argument).generate(request)
            try:
                data = self.persistentStorage.get(request.args[b'code'][0])
            except KeyError:
                return InvalidTokenError('authorization code').generate(request)
            if data['client_id'] != request.args[b'client_id'][0]:
                return InvalidParameterError('client_id').generate(request)
            if data['redirect_uri'] != request.args[b'redirect_uri'][0]:
                return InvalidParameterError('redirect_uri').generate(request)
            try:
                client = self.clientStorage.getClient(request.args[b'client_id'][0])
            except KeyError:
                return InvalidParameterError('client_id').generate(request)
            if client.clientSecret != request.args[b'client_secret'][0]:
                return InvalidParameterError('client_secret').generate(request)
            additionalData = data['additional_data']
            scope = data['scope']
            accessToken = self.tokenFactory.generateToken(
                self.authTokenLifeTime, client, scope=scope, additionalData=additionalData)
            if not self.isValidToken(accessToken):
                raise ValueError('Generated token is invalid: {token}'.format(token=accessToken))
            expireTime = None
            if self.authTokenLifeTime is not None:
                expireTime = int(time.time()) + self.authTokenLifeTime
            self.getTokenStorageSingleton().store(
                accessToken, client, scope=scope,
                additionalData=additionalData, expireTime=expireTime)
            refreshToken = None
            if self.authTokenLifeTime is not None:
                refreshToken = self.tokenFactory.generateToken(None, client, scope=scope,
                                                               additionalData=additionalData)
                if not self.isValidToken(refreshToken):
                    raise ValueError('Generated token is invalid: {token}'
                                     .format(token=refreshToken))
                self.refreshTokenStorage.store(refreshToken, client, scope=scope,
                                               additionalData=additionalData)
            return self.buildResponse(request, accessToken, refreshToken)
        else:
            return NoResource() # TODO

    def isValidToken(self, token):
        """
        Check if a token conforms tho the OAuth2 specification.
        See https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/#token

        :param token: The token to check.
        :return: True, if the token conforms to the specification, False otherwise
        """
        for char in token:
            if char not in self.VALID_TOKEN_CHARS:
                return False
        return True

    def buildResponse(self, request, accessToken, refreshToken=None):
        """
        Helper method for render_POST to generate a response
        with an access token and an optional refresh token.

        :param request: The POST request.
        :param accessToken: The access token to send back.
        :param refreshToken: An optional refresh token to send back.
        :return: A response as as a json string.
        """
        result = {
            'access_token': accessToken,
            'token_type': 'Bearer'
        }
        if self.authTokenLifeTime is not None:
            result['expires_in'] = self.authTokenLifeTime
        if refreshToken is not None:
            result['refresh_token'] = refreshToken
        request.setHeader('Content-Type', 'application/json;charset=UTF-8')
        request.setHeader('Cache-Control', 'no-store')
        request.setHeader('Pragma', 'no-cache')
        return json.dumps(result).encode('utf-8')

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
