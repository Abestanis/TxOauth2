# Copyright (c) Sebastian Scholz
# See LICENSE for details.
import time
from twisted.web.resource import Resource
from urllib import urlencode

from twisted.web.server import NOT_DONE_YET

from .errors import MissingParameterError, InsecureConnectionError, InvalidRedirectUriError,\
    UserDeniesAuthorization, InvalidClientIdError
from .token import TokenResource


class OAuth2(Resource, object):
    """
    This resource serves all the Endpoints necessary for oauth2.

    Authentication Flow:
    1: Request to this resource[/authorizePath] with query parameters
       state, client_id, response_type, scope, and redirect_uri.
    2: onAuthenticate is called. At this point one could redirect to a login page an then send
       the user back when they are logged in.
    3: onAuthenticate returns a html page which explains the user that they allow the service
       'client_id' access to all resources which require the permissions in 'scope'
    4: If the user agrees, they should be able to submit a form which will generate a POST
       request back to this resource[/authorizePath]
    5: render_POST is called. If the user agreed, render_POST should call 'return grandAccess'
    6: grandAccess generates an authentication code and redirects the user to 'redirect_uri'
       with the authentication code as the 'code' query parameter.

    """

    tokenFactory = None
    persistentStorage = None
    clientStorage = None
    allowInsecureRequestDebug = False

    def __init__(self, tokenFactory, persistentStorage, clientStorage,
                 allowInsecureRequestDebug=False):
        super(OAuth2, self).__init__()
        self.tokenFactory = tokenFactory
        self.persistentStorage = persistentStorage
        self.clientStorage = clientStorage
        self.allowInsecureRequestDebug = allowInsecureRequestDebug

    @classmethod
    def initFromTokenResource(cls, tokenResource, subPath=None, *args, **kwargs):
        if not issubclass(cls, OAuth2):
            raise ValueError('The class must be a subclass of OAuth2')
        oAuth2Resource = cls(tokenResource.tokenFactory, tokenResource.persistentStorage,
                             tokenResource.clientStorage, tokenResource.allowInsecureRequestDebug,
                             *args, **kwargs)
        if subPath is not None:
            oAuth2Resource.putChild(subPath, tokenResource)
        return oAuth2Resource

    def render_GET(self, request):
        # First check for errors where we should not redirect
        if 'client_id' not in request.args:
            return MissingParameterError(name='client_id').generate(request)
        clientId = request.args['client_id'][0]
        try:
            client = self.clientStorage.getClient(clientId)
        except KeyError:
            return InvalidClientIdError().generate(request)
        if 'redirect_uri' not in request.args:
            return MissingParameterError(name='redirect_uri').generate(request)
        redirectUri = request.args['redirect_uri'][0]
        if not redirectUri.startswith('https') or redirectUri not in client.redirectUris:
            return InvalidRedirectUriError().generate(request)
        # No validate the other requirements
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError().generate(request, redirectUri)
        for argument in ['state', 'response_type', 'scope']:
            if argument not in request.args:
                return MissingParameterError(name=argument).generate(request, redirectUri)
        return self.onAuthenticate(
            request, client, request.args['response_type'][0],
            request.args['scope'][0].split(), redirectUri, request.args['state'][0])

    def onAuthenticate(self, request, client, responseType, scope, redirectUri, state):
        raise NotImplementedError()

    def denyAccess(self, request, state, redirectUri):
        return UserDeniesAuthorization(state).generate(request, redirectUri)

    def grantAccess(self, request, client, scope, state, redirectUri,
                    lifeTime=120, additionalData=None):
        if not self.allowInsecureRequestDebug and not request.isSecure():
            return InsecureConnectionError().generate(request, redirectUri)
        code = self.tokenFactory.generateToken(client, lifeTime, scope, additionalData=additionalData)
        self.persistentStorage.put(code, {
            "redirect_uri": redirectUri,
            "client_id": client.clientId,
            "scope": scope,
            "additional_data": additionalData
        }, expireTime=int(time.time()) + lifeTime)
        queryParameter = urlencode({'state': state, 'code': code})
        request.redirect(redirectUri + '?' + queryParameter)
        request.finish()
        return NOT_DONE_YET
