# Copyright (c) Sebastian Scholz
# See LICENSE for details.

from twisted.web.resource import Resource, NoResource
import json

from .errors import InsecureConnectionError, MissingParameterError,\
    InvalidParameterError, InvalidTokenError


class TokenFactory(object):
    def generateToken(self):
        raise NotImplementedError()


class TokenStorage(object):
    def contains(self, token):
        raise NotImplementedError()

    def store(self, token, expireTime=None):
        raise NotImplementedError()


class PersistentStorage(object):
    def put(self, key, data, expireTime=None):
        raise NotImplementedError()

    def get(self, key):
        # Raise KeyError if no entry with key exists
        raise NotImplementedError()


class TokenResource(Resource, object):

    tokenFactory = None
    persistentStorage = None
    allowInsecureRequestDebug = False
    refreshTokenStorage = None
    authTokenStorage = None
    clientStorage = None
    authTokenLifeTime = 3600

    def __init__(self, tokenFactory, persistentStorage, refreshTokenStorage, authTokenStorage,
                 clientStorage, authTokenLifeTime=3600, allowInsecureRequestDebug=False):
        super(TokenResource, self).__init__()
        self.allowedMethods = ['POST']
        self.allowInsecureRequestDebug = allowInsecureRequestDebug
        self.refreshTokenStorage = refreshTokenStorage
        self.authTokenStorage = authTokenStorage
        self.tokenFactory = tokenFactory
        self.persistentStorage = persistentStorage
        self.clientStorage = clientStorage
        self.authTokenLifeTime = authTokenLifeTime

    def render_POST(self, request):
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError().generate(request)
        if 'grant_type' not in request.args:
            return MissingParameterError(name='grant_type')
        if request.args['grant_type'][0] == 'authorization_code':
            for argument in ['client_id', 'client_secret', 'code', 'redirect_uri']:
                if argument not in request.args:
                    return MissingParameterError(name=argument).generate(request)
            try:
                data = self.persistentStorage.get(request.args['code'][0])
            except KeyError:
                return InvalidTokenError("authorization code").generate(request)
            data = json.loads(data)
            if data['client_id'] != request.args['client_id'][0] or data['redirect_uri'] != request.args['redirect_uri'][0]:
                return InvalidParameterError("Invalid client_id or redirect_uri").generate(request)
            try:
                client = self.clientStorage.getClient(request.args['client_id'][0])
            except KeyError:
                return InvalidParameterError("Invalid client_id").generate(request)
            if client.clientSecret != request.args['client_secret'][0]:
                return InvalidParameterError("Invalid client_secret").generate(request)
            accessToken = self.tokenFactory.generateToken()
            self.authTokenStorage.store(accessToken, expireTime=self.authTokenLifeTime if self.authTokenLifeTime > 0 else None)
            result = {
                "access_token": accessToken,
                "token_type": "Bearer"
            }
            if self.authTokenLifeTime > 0:
                refreshToken = self.tokenFactory.generateToken()
                self.refreshTokenStorage.store(refreshToken)
                result["refresh_token"] = refreshToken
                result["expires_in"] = self.authTokenLifeTime
            request.setHeader("Content-Type", "application/json;charset=UTF-8")
            request.setHeader("Cache-Control", "no-store")
            request.setHeader("Pragma", "no-cache")
            return json.dumps(result).encode("utf-8")
        else:
            return NoResource() # TODO
