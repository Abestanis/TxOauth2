# Copyright (c) Sebastian Scholz
# See LICENSE for details.
import string
import time
from twisted.web.resource import Resource, NoResource
import json

from .errors import InsecureConnectionError, MissingParameterError, \
    InvalidParameterError, InvalidTokenError, InvalidScopeError


class TokenFactory(object):
    def generateToken(self, lifetime, client, scope, additionalData=None):
        raise NotImplementedError()


class TokenStorage(object):
    def contains(self, token, scope):
        raise NotImplementedError()

    def getTokenData(self, token):
        raise NotImplementedError()

    def store(self, token, client, scope, additionalData=None, expireTime=None):
        raise NotImplementedError()


class PersistentStorage(object):
    def put(self, key, data, expireTime=None):
        raise NotImplementedError()

    def get(self, key):
        # Raise KeyError if no entry with key exists
        raise NotImplementedError()


class TokenResource(Resource, object):
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
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError().generate(request)
        if 'grant_type' not in request.args:
            return MissingParameterError(name='grant_type')
        if request.args['grant_type'][0] == 'refresh_token':
            for argument in ['client_id', 'client_secret', 'refresh_token']:
                if argument not in request.args:
                    return MissingParameterError(name=argument).generate(request)
            try:
                client = self.clientStorage.getClient(request.args['client_id'][0])
            except KeyError:
                return InvalidParameterError("client_id").generate(request)
            if client.clientSecret != request.args['client_secret'][0]:
                return InvalidParameterError("client_secret").generate(request)
            refreshToken = request.args['refresh_token'][0]
            try:
                scope, additionalData = self.refreshTokenStorage.getTokenData(refreshToken)
            except KeyError:
                return InvalidTokenError("refresh token").generate(request)
            if 'scope' in request.args:
                if scope != request.args['scope'][0]: # TODO: Support multiple scopes
                    return InvalidScopeError(request.args['scope'][0]).generate(request)
                scope = request.args['scope'][0]
            if not self.refreshTokenStorage.contains(refreshToken, scope):
                return InvalidTokenError("refresh token").generate(request)
            accessToken = self.tokenFactory.generateToken(client, scope=scope,
                                                          additionalData=additionalData)
            if not self.isValidToken(accessToken):
                raise ValueError('Generated token is invalid: {token}'.format(token=accessToken))
            expireTime = None
            if self.authTokenLifeTime > 0:
                expireTime = int(time.time()) + self.authTokenLifeTime
            self.getTokenStorageSingleton().store(
                accessToken, client, scope=scope,
                additionalData=additionalData, expireTime=expireTime)
            return self.buildResponse(request, accessToken)
        elif request.args['grant_type'][0] == 'authorization_code':
            for argument in ['client_id', 'client_secret', 'code', 'redirect_uri']:
                if argument not in request.args:
                    return MissingParameterError(name=argument).generate(request)
            try:
                data = self.persistentStorage.get(request.args['code'][0])
            except KeyError:
                return InvalidTokenError("authorization code").generate(request)
            if data['client_id'] != request.args['client_id'][0] or\
               data['redirect_uri'] != request.args['redirect_uri'][0]:
                return InvalidParameterError("client_id or redirect_uri").generate(request)
            try:
                client = self.clientStorage.getClient(request.args['client_id'][0])
            except KeyError:
                return InvalidParameterError("client_id").generate(request)
            if client.clientSecret != request.args['client_secret'][0]:
                return InvalidParameterError("client_secret").generate(request)
            additionalData = data['additional_data']
            scope = data['scope']
            accessToken = self.tokenFactory.generateToken(client, scope=scope,
                                                          additionalData=additionalData)
            if not self.isValidToken(accessToken):
                raise ValueError('Generated token is invalid: {token}'.format(token=accessToken))
            expireTime = None
            if self.authTokenLifeTime > 0:
                expireTime = int(time.time()) + self.authTokenLifeTime
            self.getTokenStorageSingleton().store(
                accessToken, client, scope=scope,
                additionalData=additionalData, expireTime=expireTime)
            refreshToken = None
            if self.authTokenLifeTime > 0:
                refreshToken = self.tokenFactory.generateToken(client, scope=scope,
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
        for char in token:
            if char not in self.VALID_TOKEN_CHARS:
                return False
        return True

    def buildResponse(self, request, accessToken, refreshToken=None):
        result = {
            "access_token": accessToken,
            "token_type": "Bearer"
        }
        if self.authTokenLifeTime > 0:
            result["expires_in"] = self.authTokenLifeTime
        if refreshToken is not None:
            result["refresh_token"] = refreshToken
        request.setHeader("Content-Type", "application/json;charset=UTF-8")
        request.setHeader("Cache-Control", "no-store")
        request.setHeader("Pragma", "no-cache")
        return json.dumps(result).encode("utf-8")

    @staticmethod
    def getTokenStorageSingleton():
        if TokenResource._OAuthTokenStorage is None:
            raise ValueError('The access token storage is not initialized')
        return TokenResource._OAuthTokenStorage
