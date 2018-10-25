# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" The authorization endpoint. """
import logging
import time

from uuid import uuid4
from abc import ABCMeta, abstractmethod
try:
    from urlparse import urlparse
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse

from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from txoauth2.util import addToUrl
from txoauth2.granttypes import GrantTypes
from .errors import MissingParameterError, InsecureConnectionError, InvalidRedirectUriError, \
    UserDeniesAuthorization, UnsupportedResponseTypeError, \
    UnauthorizedClientError, ServerError, AuthorizationError, MalformedParameterError, \
    MultipleParameterError, InvalidScopeError, InvalidParameterError


class InvalidDataKeyError(KeyError):
    """
    Exception that is raised when an invalid or expired
    data key is passed to denyAccess or grantAccess.
    """
    pass


class InsecureRedirectUriError(RuntimeError):
    """ Exception that is raised when an insecure redirect uri is used in grantAccess. """
    pass


class OAuth2(Resource, object):
    """
    This resource handles the authorization process by the user.

    Clients that want to get tokens need to send the user to
    this resource to start the authorization process.
    While configuring the client, one needs to specify the address
    of this resource as the "Authorization Endpoint".

    Authorization Code Grant Flow:
    1: A client sends the user to this resource and sends the parameter state, client_id,
       response_type, scope, and redirect_uri as query parameters of the (GET) request.
    2: After validating the parameters, this class calls onAuthenticate. At this point one
       could redirect to a login page an then send the user back when they are logged in.
    3: onAuthenticate need to show the user a html page which explains that they allow the client
       access to all resources which require the permissions in 'scope'.
    4a: If the user denies access, you need to call denyAccess.
    4b: If the user agrees, you need to call grantAccess and the user is then redirected to
        one of the returnUris of the client. The request to the redirect url will contain a
        code in the url parameters. The code does not grant access to the scope and has a very
        short lifetime.
    5: The client uses the code to get a token from the TokenEndpoint.

    Implicit Grant Flow:
    1 - 4a: Same as in the Authorization Code Grant.
    4b: If the user agrees, you need to call grantAccess and the user is then redirected to
        one of the returnUris of the client. The request to the redirect url will contain an
        authorization token in the url parameters, which the client can use to access
        the resources indicated by the scope.

    """
    __metaclass__ = ABCMeta
    acceptedGrantTypes = [GrantTypes.AuthorizationCode.value, GrantTypes.Implicit.value]
    requestDataLifetime = 3600
    authTokenLifeTime = 3600
    allowInsecureRequestDebug = False
    defaultScope = None
    _tokenFactory = None
    _persistentStorage = None
    _clientStorage = None
    _authTokenStorage = None

    def __init__(self, tokenFactory, persistentStorage, clientStorage,
                 requestDataLifeTime=3600, authTokenLifeTime=3600, allowInsecureRequestDebug=False,
                 grantTypes=None, authTokenStorage=None, defaultScope=None):
        """
        Creates a new OAuth2 Resource.

        :param tokenFactory: A tokenFactory to generate short lived tokens.
        :param persistentStorage: A persistent storage that can be accessed by the TokenResource.
        :param clientStorage: A handle to the storage of known clients.
        :param requestDataLifeTime: The lifetime of the data stored for an authorization request in
                                    seconds. Essentially the maximum amount of time that can pass
                                    between the call to onAuthenticate and deny-/grantAccess.
        :param authTokenLifeTime: The lifetime of the tokens generated during .
        :param allowInsecureRequestDebug: If True, allow requests over insecure connections.
                                          Do NOT use in production!
        :param grantTypes: The grant types that are enabled for this authorization endpoint.
        :param authTokenStorage: The token storage in which to store tokens generated in the
                                 implicit grant flow. Only needed if the implicit flow is enabled.
                                 Must be the same as the one passed to the token resource.
        :param defaultScope: A list of scopes that should be used as a default
                             for authorization requests if they don't provide one.
        """
        super(OAuth2, self).__init__()
        self._tokenFactory = tokenFactory
        self._persistentStorage = persistentStorage
        self._clientStorage = clientStorage
        self._authTokenStorage = authTokenStorage
        self.allowInsecureRequestDebug = allowInsecureRequestDebug
        self.requestDataLifetime = requestDataLifeTime
        self.authTokenLifeTime = authTokenLifeTime
        if authTokenLifeTime is None:
            raise ValueError('Authentication tokens generated with the '
                             'implicit grant flow need a limited lifetime.')
        if grantTypes is not None:
            for grantType in [GrantTypes.RefreshToken, GrantTypes.Password,
                              GrantTypes.ClientCredentials]:
                if grantType in grantTypes:
                    grantTypes.remove(grantType)
            grantTypes = [grantType.value if isinstance(grantType, GrantTypes) else grantType
                          for grantType in grantTypes]
            self.acceptedGrantTypes = grantTypes
        if defaultScope is not None:
            self.defaultScope = defaultScope
        if GrantTypes.Implicit.value in self.acceptedGrantTypes and self._authTokenStorage is None:
            raise ValueError('The token storage can not be None '
                             'when the implicit authorization flow is enabled')

    @classmethod
    def initFromTokenResource(cls, tokenResource, *args, **kwargs):
        """
        Create an OAuth2 Resource with the tokenFactory, the persistentStorage
        and the clientStorage of the tokenResource. The allowInsecureRequestDebug
        flag is also copied.
        If a subPath keyword argument is given, the tokenResource is added as a child to the new
        OAuth2 Resource at the subPath.

        :param tokenResource: The TokenResource to initialize the new OAuth2 Resource.
        :param args: Arguments to the for the classes constructor.
        :param kwargs: Keyword arguments to the for the classes constructor.
        :return: A new initialized OAuth2 Resource.
        """
        keywordArgs = {
            'authTokenLifeTime': tokenResource.authTokenLifeTime,
            'allowInsecureRequestDebug': tokenResource.allowInsecureRequestDebug,
            'authTokenStorage': tokenResource.getTokenStorageSingleton(),
            'defaultScope': tokenResource.defaultScope
        }
        keywordArgs.update(kwargs)
        subPath = keywordArgs.pop('subPath', None)
        oAuth2Resource = cls(tokenResource.tokenFactory, tokenResource.persistentStorage,
                             tokenResource.clientStorage, *args, **keywordArgs)
        if subPath is not None:
            oAuth2Resource.putChild(subPath, tokenResource)
        return oAuth2Resource

    def render_GET(self, request):  # pylint: disable=invalid-name
        """
        Handle a GET request to this resource. This initializes
        the authorization process.

        All parameter necessary for authorization are parsed from the
        request and on onAuthenticate is called with the parsed arguments.

        :param request: The GET request.
        :return: A response or NOT_DONE_YET
        """
        if b'client_id' not in request.args:
            return MissingParameterError('client_id').generate(request)
        if len(request.args[b'client_id']) != 1:
            return MultipleParameterError('client_id').generate(request)
        try:
            clientId = request.args[b'client_id'][0].decode('utf-8')
        except UnicodeDecodeError:
            return MalformedParameterError('client_id').generate(request)
        try:
            client = self._clientStorage.getClient(clientId)
        except KeyError:
            return InvalidParameterError('client_id').generate(request)
        if b'redirect_uri' not in request.args:
            if len(client.redirectUris) != 1:
                return MissingParameterError('redirect_uri').generate(request)
            redirectUri = client.redirectUris[0]
        elif len(request.args[b'redirect_uri']) != 1:
            return MultipleParameterError('redirect_uri').generate(request)
        else:
            try:
                redirectUri = request.args[b'redirect_uri'][0].decode('utf-8')
            except UnicodeDecodeError:
                return MalformedParameterError('redirect_uri').generate(request)
        if redirectUri not in client.redirectUris:
            return InvalidRedirectUriError().generate(request)
        try:
            errorInFragment = request.args[b'response_type'][0].decode('utf-8') == 'token'
        except (UnicodeDecodeError, KeyError, IndexError):
            errorInFragment = False
        if b'state' in request.args and len(request.args[b'state']) != 1:
            return MultipleParameterError('state').generate(request, redirectUri, errorInFragment)
        state = request.args.get(b'state', [None])[0]
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError(state).generate(request, redirectUri, errorInFragment)
        if b'response_type' not in request.args:
            return MissingParameterError('response_type', state=state)\
                .generate(request, redirectUri, errorInFragment)
        elif len(request.args[b'response_type']) != 1:
            return MultipleParameterError('response_type', state=state)\
                .generate(request, redirectUri, errorInFragment)
        try:
            responseType = request.args[b'response_type'][0].decode('utf-8')
        except UnicodeDecodeError:
            return MalformedParameterError('response_type', state)\
                .generate(request, redirectUri, errorInFragment)
        errorInFragment = responseType == 'token'
        if b'scope' not in request.args:
            if self.defaultScope is None:
                return MissingParameterError('scope', state=state)\
                    .generate(request, redirectUri, errorInFragment)
            scope = self.defaultScope
        elif len(request.args[b'scope']) != 1:
            return MultipleParameterError('scope', state=state)\
                .generate(request, redirectUri, errorInFragment)
        else:
            try:
                scope = request.args[b'scope'][0].decode('utf-8').split()
            except UnicodeDecodeError:
                return InvalidScopeError(request.args[b'scope'][0], state=state)\
                    .generate(request, redirectUri, errorInFragment)
        grantType = responseType
        if responseType == 'code':
            grantType = GrantTypes.AuthorizationCode.value
        elif responseType == 'token':
            grantType = GrantTypes.Implicit.value
        if grantType not in self.acceptedGrantTypes:
            return UnsupportedResponseTypeError(responseType, state)\
                .generate(request, redirectUri, errorInFragment)
        if grantType not in client.authorizedGrantTypes:
            return UnauthorizedClientError(responseType, state)\
                .generate(request, redirectUri, errorInFragment)
        return self._handleAuthenticationRequest(
            request, client, grantType, redirectUri, scope, state, errorInFragment)

    @abstractmethod
    def onAuthenticate(self, request, client, responseType, scope, redirectUri, state, dataKey):
        """
        Called when a valid GET request is made to this OAuth2 resource.
        This happens when a clients sends a user to this resource.

        The user should be presented with a website that clearly informs him
        that he can give access all or a subset of the scopes to the client.
        He must have the option to allow or deny the request.

        It is also possible to redirect the user to a different site
        here (e.g. to a login page).

        If the user grants access, call 'grantAccess' with the dataKey.
        If the user denies access, call 'denyAccess' with the dataKey.

        If the redirect uri does not use TSL, the user should be warned,
        because it severely impacts the security of the authorization process.
        (See https://tools.ietf.org/html/rfc6749#section-3.1.2.1)

        If this method determines that the received request is not valid,
        it should return an instance of an AuthorizationError.

        :param request: The GET request.
        :param client: The client that sent the user.
        :param responseType: The OAuth2 response type (one of the values in _acceptedGrantTypes).
        :param scope: The list of scopes that the client requests access to.
        :param redirectUri: The uri the user should get redirected to
                            after he grants or denies access.
        :param state: The state that was send by the client.
        :param dataKey: This key is tied to this request
                        and must be passed to denyAccess or grantAccess.
        :return: A response or NOT_DONE_YET
        """
        raise NotImplementedError()

    def denyAccess(self, request, dataKey):
        """
        The user denies access to the requested scopes.
        This method redirects the user to the redirectUri
        with an access_denied parameter, as required
        by the OAuth2 spec.

        The request will be closed and can't be written
        to after this function returns.

        :raises InvalidDataKeyError: If the given data key is invalid or expired.
        :param request: The request made by the user.
        :param dataKey: The data key that was given to onAuthenticate.
        :return: NOT_DONE_YET
        """
        try:
            data = self._persistentStorage.pop(dataKey)
        except KeyError:
            raise InvalidDataKeyError(dataKey)
        errorInFragment = data['response_type'] == GrantTypes.Implicit.value
        redirectUri = data['redirect_uri']
        if redirectUri is None:
            try:
                client = self._clientStorage.getClient(data['client_id'])
            except KeyError:
                return InvalidParameterError('client_id') \
                    .generate(request, redirectUri, errorInFragment)
            redirectUri = client.redirectUris[0]
        return UserDeniesAuthorization(data['state'])\
            .generate(request, redirectUri, errorInFragment)

    def grantAccess(self, request, dataKey, scope=None, codeLifeTime=120, additionalData=None,
                    allowInsecureRedirectUri=False):
        """
        The user grants access to the list of scopes. This list may
        contain less values than the original list passed to onAuthenticate.

        The user will be redirected to the redirectUri with a code or a
        token as a parameter, depending on the responseType.

        The request will be closed and can't be written
        to after this function returns.

        :raises InvalidDataKeyError: If the given data key is invalid or expired.
        :raises InsecureRedirectUriError: If the given redirect uri is not
                using a secure scheme and insecure connections are not allowed.
        :raises ValueError: If the data key belongs to a request with a custom response type.
        :param request: The request made by the user.
        :param dataKey: The allowInsecureRedirectUri is false and the redirect uri is not secure.
        :param scope: The scope the user grants the client access to.
                      Must be None (=> the same) or a subset of the scope given to onAuthenticate.
        :param codeLifeTime: The lifetime of the generated code, if responseType is 'code'.
                             This code can be used at the TokenResource to get a real token.
                             The code itself is not a token and should expire soon.
        :param additionalData: Any additional data that should be passed associated
                               with the generated tokens.
        :param allowInsecureRedirectUri: If false, this method will throw a InsecureRedirectUriError
                                         if the redirect uri does not use TLS (https).
        :return: NOT_DONE_YET
        """
        try:
            data = self._persistentStorage.pop(dataKey)
        except KeyError:
            raise InvalidDataKeyError(dataKey)
        state = data['state']
        responseType = data['response_type']
        errorInFragment = responseType == GrantTypes.Implicit.value
        if responseType not in [GrantTypes.AuthorizationCode.value, GrantTypes.Implicit.value]:
            self._persistentStorage.put(
                dataKey, data, expireTime=int(time.time()) + self.requestDataLifetime)
            raise ValueError(responseType)
        redirectUri = data['redirect_uri']
        try:
            client = self._clientStorage.getClient(data['client_id'])
        except KeyError:
            return InvalidParameterError('client_id')\
                .generate(request, redirectUri, errorInFragment)
        if redirectUri is None:
            redirectUri = client.redirectUris[0]
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError(state).generate(request, redirectUri, errorInFragment)
        if not allowInsecureRedirectUri and urlparse(redirectUri).scheme != 'https':
            self._persistentStorage.put(
                dataKey, data, expireTime=int(time.time()) + self.requestDataLifetime)
            raise InsecureRedirectUriError()
        if scope is not None:
            for acceptedScope in scope:
                if acceptedScope not in data['scope']:
                    return InvalidScopeError(scope, state)\
                        .generate(request, redirectUri, errorInFragment)
        else:
            scope = data['scope']
        if responseType == GrantTypes.AuthorizationCode.value:
            code = self._tokenFactory.generateToken(
                client, codeLifeTime, scope, additionalData=additionalData)
            self._persistentStorage.put('code' + code, {
                'client_id': client.id,
                'redirect_uri': redirectUri,
                'additional_data': additionalData,
                'scope': scope
            }, expireTime=int(time.time()) + codeLifeTime)
            redirectUri = addToUrl(redirectUri, query={'state': state, 'code': code})
        else:
            token = self._tokenFactory.generateToken(
                self.authTokenLifeTime, client, scope, additionalData=additionalData)
            self._authTokenStorage.store(token, client, scope, additionalData=additionalData,
                                         expireTime=int(time.time()) + self.authTokenLifeTime)
            redirectUri = addToUrl(redirectUri, fragment={
                'state': state, 'access_token': token, 'token_type': 'Bearer',
                'expires_in': self.authTokenLifeTime, 'scope': ' '.join(scope)})
        request.redirect(redirectUri)
        request.finish()
        return NOT_DONE_YET

    def _handleAuthenticationRequest(
            self, request, client, grantType, redirectUri, scope, state, errorInFragment):
        """
        handle an authentication request. The request has already been validated.

        :param request: The request.
        :param client: The client that initiated the request.
        :param grantType: The grant type of the request.
        :param redirectUri: The uri to redirect the user to
                            after the request was accepted or denied.
        :param scope: The scope that the request requests access to.
        :param state: The state parameter of the request.
        :param errorInFragment: Whether or not the error should be send in the query or fragment.
        :return: The result of the request.
        """
        dataKey = 'request' + str(uuid4())
        self._persistentStorage.put(dataKey, {
            'response_type': grantType,
            'redirect_uri': None if b'redirect_uri' not in request.args else redirectUri,
            'client_id': client.id,
            'scope': scope,
            'state': state
        }, expireTime=int(time.time()) + self.requestDataLifetime)
        try:
            result = self.onAuthenticate(request, client, grantType, scope,
                                         redirectUri, state, dataKey)
        except Exception as error:  # pylint: disable=broad-except
            logging.getLogger('txOauth2').error(
                'Caught exception in onAuthenticate: %s', str(error), exc_info=1)
            return ServerError(state).generate(request, redirectUri, errorInFragment)
        if isinstance(result, AuthorizationError):
            return result.generate(request, redirectUri, errorInFragment)
        return result
