# Copyright (c) Sebastian Scholz
# See LICENSE for details.
import time

try:
    from urllib import urlencode
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlencode

from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from .errors import MissingParameterError, InsecureConnectionError, InvalidRedirectUriError,\
    UserDeniesAuthorization, InvalidClientIdError


class OAuth2(Resource, object):
    """
    This resource handles the authorization process by the user.

    Clients that want to get tokens need to send the user to
    this resource to start the authorization process.
    While configuring the client, one needs to specify the address
    of this resource as the "Authorization Endpoint".

    Authorization Flow:
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

    """

    tokenFactory = None
    persistentStorage = None
    clientStorage = None
    allowInsecureRequestDebug = False

    def __init__(self, tokenFactory, persistentStorage, clientStorage,
                 allowInsecureRequestDebug=False):
        """
        Creates a new OAuth2 Resource.

        :param tokenFactory: A tokenFactory to generate short lived tokens.
        :param persistentStorage: A persistent storage that can be accessed by the TokenResource.
        :param clientStorage: A handle to the storage of known clients.
        :param allowInsecureRequestDebug: If True, allow requests over insecure connections.
                                          Do NOT use in production!
        """
        super(OAuth2, self).__init__()
        self.tokenFactory = tokenFactory
        self.persistentStorage = persistentStorage
        self.clientStorage = clientStorage
        self.allowInsecureRequestDebug = allowInsecureRequestDebug

    @classmethod
    def initFromTokenResource(cls, tokenResource, subPath=None, *args, **kwargs):
        """
        Create an OAuth2 Resource with the tokenFactory, the persistentStorage
        and the clientStorage of the tokenResource. The allowInsecureRequestDebug
        flag is also copied.
        If a subPath is given, the tokenResource is added as a child to the new
        OAuth2 Resource at the subPath.

        :param tokenResource: The TokenResource to initialize the new OAuth2 Resource.
        :param subPath: An optional path at which the tokenResource will be added.
        :param args: Additional arguments to the for the classes __init__ function.
        :param kwargs: Additional keyword arguments to the for the classes __init__ function.
        :return: A new initialized OAuth2 Resource.
        """
        if not issubclass(cls, OAuth2):
            raise ValueError('The class must be a subclass of OAuth2')
        oAuth2Resource = cls(tokenResource.tokenFactory, tokenResource.persistentStorage,
                             tokenResource.clientStorage, tokenResource.allowInsecureRequestDebug,
                             *args, **kwargs)
        if subPath is not None:
            oAuth2Resource.putChild(subPath, tokenResource)
        return oAuth2Resource

    def render_GET(self, request):
        """
        Handle a GET request to this resource. This initializes
        the authorization process.

        All parameter necessary for authorization are parsed from the
        request and on onAuthenticate is called with the parsed arguments.

        :param request: The GET request.
        :return: A response or NOT_DONE_YET
        """
        # First check for errors where we should not redirect
        if b'client_id' not in request.args:
            return MissingParameterError(name='client_id').generate(request)
        try:
            clientId = request.args[b'client_id'][0].decode('utf-8')
            client = self.clientStorage.getClient(clientId)
        except (KeyError, UnicodeDecodeError):
            return InvalidClientIdError().generate(request)
        if b'redirect_uri' not in request.args:
            return MissingParameterError(name='redirect_uri').generate(request)
        redirectUri = request.args[b'redirect_uri'][0].decode('utf-8')
        if not redirectUri.startswith('https') or redirectUri not in client.redirectUris:
            return InvalidRedirectUriError().generate(request)
        # No validate the other requirements
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError().generate(request, redirectUri)
        for argument in [b'state', b'response_type', b'scope']:
            if argument not in request.args:
                return MissingParameterError(name=argument).generate(request, redirectUri)
        return self.onAuthenticate(
            request, client, request.args[b'response_type'][0].decode('utf-8'),
            request.args[b'scope'][0].decode('utf-8').split(),
            redirectUri, request.args[b'state'][0])

    def onAuthenticate(self, request, client, responseType, scope, redirectUri, state):
        """
        Called when a GET request is made to the OAuth2 resource.
        This happens when a clients sends a user to this resource.

        The user should be presented with a website that clearly
        informs him, that he can give access to the scopes to the
        client. He must have the option to allow or deny the request.

        Optionally, he should be able to select the scopes he wants
        to grant access to.

        It is also possible to redirect the user to a different site
        here (e.g. to a login page).

        If the user grants access, call 'grantAccess'.
        If the user denies access, call 'denyAccess'.

        :param request: The GET request.
        :param client: The client that sent the user.
        :param responseType: The OAuth2 response type ('code' or 'token').
        :param scope: The list of scopes that the client requests access to.
        :param redirectUri: The uri the user should get redirected to
               after he grants or denies access.
        :param state: A parameter that is send by the client und must
               be send back unaltered in the response.
        :return: A response or NOT_DONE_YET
        """
        raise NotImplementedError()

    def denyAccess(self, request, state, redirectUri):
        """
        The user denies access to the requested scopes.
        This method redirects the user to the redirectUri
        with an access_denied parameter, as required
        by the OAuth2 spec.

        The request will be closed and can't be written
        to after this function returns.

        :param request: The request made by the user.
        :param state: The state parameter that was given to onAuthenticate.
        :param redirectUri: The redirect target as given to onAuthenticate.
        :return: NOT_DONE_YET
        """
        return UserDeniesAuthorization(state).generate(request, redirectUri)

    def grantAccess(self, request, client, scope, state, redirectUri, responseType,
                    codeLifeTime=120, additionalData=None):
        """
        The user grants access to the list of scopes. This list may
        contain less values than the original list passed to onAuthenticate.

        The user will be redirected to the redirectUri with a code or a
        token as a parameter, depending on the responseType.

        The request will be closed and can't be written
        to after this function returns.

        :param request: The request made by the user.
        :param client: The client that the user grants access.
        :param scope: The list of scopes the user grants access to.
        :param state: The state parameter that was given to onAuthenticate.
        :param redirectUri: The redirect target as given to onAuthenticate.
        :param responseType: The responseType as given to onAuthenticate.
        :param codeLifeTime: The lifetime of the generated code, if responseType is 'code'.
                             This code can be used at the TokenResource to get a real token.
                             The code itself is not a token and should expire soon.
        :param additionalData: Any additional data that should be passed associated
                               with the generated tokens.
        :return: NOT_DONE_YET
        """
        # TODO: Handle token responseType
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError().generate(request, redirectUri)
        code = self.tokenFactory.generateToken(client, codeLifeTime, scope,
                                               additionalData=additionalData)
        self.persistentStorage.put(code, {
            'redirect_uri': redirectUri,
            'client_id': client.clientId,
            'scope': scope,
            'additional_data': additionalData
        }, expireTime=int(time.time()) + codeLifeTime)
        queryParameter = urlencode({'state': state, 'code': code})
        request.redirect(redirectUri + '?' + queryParameter)
        request.finish()
        return NOT_DONE_YET
