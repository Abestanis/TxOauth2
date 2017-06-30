# Copyright (c) Sebastian Scholz
# See LICENSE for details.
#
# This is an example of how to implement oauth2 with this library and twisted.
# It should not be used as is in a real server and is meant as a starting point
# to build your own implementation

import os

from twisted.internet import reactor, endpoints
from twisted.web.server import Site, NOT_DONE_YET
from twisted.web.resource import Resource
import time

from oauth2 import oauth2, isAuthorized
from oauth2.clients import Client
from oauth2.resource import OAuth2
from oauth2.token import TokenStorage, PersistentStorage, TokenResource
from oauth2.imp import UUIDTokenFactory, SimpleClientStorage


class ClockPage(Resource):
    """
    This represents a resource that should be protected via oauth2.
    
    There are two ways to protect a resource with oauth2:
    1: Use the isAuthorized function and return NOT_DONE_YET if it returns False
    2: use the oauth2 descriptor on one of the render_* functions (or any function, that accepts
       the request as the second argument) and it will call isAuthorized for you.
    
    Note that we allow requests send over http (allowInsecureRequestDebug=True). This is done
    so one could test this server locally. Do not enable it when running a real server! Don't do it!
    """
    isLeaf = True

    @oauth2('VIEW_CLOCK', allowInsecureRequestDebug=True)
    def render_GET(self, request):
        # This check is not necessary, because this method is already protected by the @oauth
        # decorator. It is included here to show of the two ways of protecting a resource.
        if not isAuthorized(request, 'VIEW_CLOCK'):
            return NOT_DONE_YET
        return "<html><body>{time}</body></html>".format(time=time.ctime())


class TokenStorageImp(TokenStorage):
    """
    This is an implementation of the TokenStorage interface.
    Check out the base class for more detail.
    
    This implementation does not implement any type of persistence, because it is not required
    for this example. Any real implementation will likely want to implement persistence to preserve
    tokens between server restarts.
    """
    tokens = {}

    def contains(self, token, scope):
        tokenEntry = self.tokens.get(token, None)
        if tokenEntry is not None:
            if tokenEntry['expires'] is not None and time.time() > tokenEntry['expires']:
                # The token expired
                del self.tokens[token]
                return False
            # Check if the token allows access to the scope
            if type(scope) != list:
                scope = [scope]
            for scopeType in scope:
                if scopeType not in tokenEntry['scope']:
                    return False
            return False
        return False

    def getTokenData(self, token):
        return self.tokens[token]['scope'], self.tokens[token]['additionalData']

    def store(self, token, client, scope, additionalData=None, expireTime=None):
        self.tokens[token] = {
            'scope': scope,
            'expires': expireTime,
            'additionalData': additionalData
        }


class PersistentStorageImp(PersistentStorage):
    """
    This implements the PersistentStorage interface. Check out the base class for more detail.
    
    As with the TokenStorageImp, this implementation does not implement any type of persistence.
    Often persistence is probably not needed here, because the lifetime of the objects stored here
    is commonly very short.
    """
    storage = {}

    def put(self, key, data, expireTime=None):
        self.storage[key] = {
            'data': data,
            'expires': expireTime
        }

    def get(self, key):
        entry = self.storage[key]
        if entry['expires'] is not None and time.time() > entry['expires']:
            del self.storage[key]
            raise KeyError(key)
        return entry['data']


class OAuth2Endpoint(OAuth2):
    """
    This is the Resource that implements the oauth2 endpoint. It will handle the user authorization
    and it hosts the token endpoint.
    
    Note: This implementation does not verify the user and does not require him to authenticate
    himself. A real implementation should probably do so.
    You are not limited to display a simple web page in onAuthenticate. It is totally valid
    to redirect to a different resource and call grantAccess from there.
    """

    def onAuthenticate(self, request, client, responseType, scope, redirectUri, state):
        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Authorization</title>
</head>
<body>
<form action="/oauth2" method="post">
<p>Allow access?</p>
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="response_type" value="{response_type}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="submit" name="confirm" value="yes">
<input type="submit" name="confirm" value="no">
</form>
</body>
</html>""".format(client_id=client.clientId, scope=" ".join(scope), response_type=responseType,
                  state=state, redirect_uri=redirectUri)

    def render_POST(self, request):
        """
        This will be called when the user clicks on the "yes" or "no" button in the page
        returned by onAuthenticate.
        """
        state = request.args['state'][0]
        redirectUri = request.args['redirect_uri'][0]
        if len(request.args.get("confirm", [])) > 0 and request.args["confirm"][0] == "yes":
            scope = request.args['scope'][0].split()
            client = self.clientStorage.getClient(request.args['client_id'][0])
            return self.grantAccess(request, client, scope, state, redirectUri)
        else:
            return self.denyAccess(request, state, redirectUri)


def setupOAuth2Clients():
    """
    Setup a client storage with a test client.
    :return: The client storage
    """
    clientStorage = SimpleClientStorage(os.path.join(os.path.dirname(__file__), 'clientStorage'))
    testClient = Client()
    testClient.clientId = 'test'
    testClient.clientSecret = 'test_secret'
    testClient.name = 'Test Client'
    testClient.redirectUris = ['https://clientServer.com/return']
    clientStorage.addClient(testClient)
    return clientStorage


def setupTestServerResource():
    """
    Setup a test server with a protected clock resource and an oauth2 endpoint.
    :return: The root resource of the test server
    """
    clientStorage = setupOAuth2Clients()
    tokenResource = TokenResource(UUIDTokenFactory(), PersistentStorageImp(), TokenStorageImp(),
                                  TokenStorageImp(), clientStorage, allowInsecureRequestDebug=True)
    root = Resource()
    root.putChild("clock", ClockPage())
    root.putChild("oauth2", OAuth2Endpoint.initFromTokenResource(tokenResource, subPath="token"))
    return root


def main():
    """
    Run a test server at localhost:8880.
    """
    factory = Site(setupTestServerResource())
    endpoint = endpoints.TCP4ServerEndpoint(reactor, 8880)
    endpoint.listen(factory)
    reactor.run()

if __name__ == '__main__':
    main()
