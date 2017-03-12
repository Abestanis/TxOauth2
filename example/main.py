# Copyright (c) Sebastian Scholz
# See LICENSE for details.

import os

from twisted.internet import reactor, endpoints
from twisted.web.server import Site, NOT_DONE_YET
from twisted.web.resource import Resource
import time

from oauth2.clients import Client
from oauth2.resource import OAuth2, isAuthorized, oauth2
from oauth2.token import TokenStorage, PersistentStorage
from oauth2.imp import UUIDTokenFactory, SimpleClientStorage


class ClockPage(Resource):
    isLeaf = True

    @oauth2('VIEW_CLOCK', allowInsecureRequestDebug=True)
    def render_GET(self, request):
        #if not isAuthorized(request, 'VIEW_CLOCK'):
        #    return NOT_DONE_YET
        return "<html><body>{time}</body></html>".format(time=time.ctime())


class TokenStorageImp(TokenStorage):
    tokens = []

    def contains(self, token):
        return token in self.tokens

    def store(self, token, expireTime=None):
        self.tokens.append(token)


class PersistentStorageImp(PersistentStorage):
    storage = {}

    def put(self, key, data, expireTime=None):
        self.storage[key] = data

    def get(self, key):
        return self.storage[key]


class OAuth2Imp(OAuth2):
    def __init__(self, clientStorage):
        super(OAuth2Imp, self).__init__(UUIDTokenFactory(), PersistentStorageImp(),
                                        TokenStorageImp(), TokenStorageImp(), clientStorage,
                                        allowInsecureRequestDebug=True)

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
        state = request.args['state'][0]
        redirectUri = request.args['redirect_uri'][0]
        if len(request.args.get("confirm", [])) > 0 and request.args["confirm"][0] == "yes":
            scopeList = request.args['scope'][0].split()
            clientId = request.args['client_id'][0]
            return self.grantAccess(request, clientId, scopeList, state, redirectUri)
        else:
            return self.denyAccess(request, state, redirectUri)


def setupOAuth2Clients():
    clientStorage = SimpleClientStorage(os.path.join(os.path.dirname(__file__), 'clientStorage'))
    testClient = Client()
    testClient.clientId = 'test'
    testClient.name = 'Test Client'
    testClient.redirectUris = ['https://clientServer.com/return']
    clientStorage.addClient(testClient)
    return clientStorage


def main():
    clientStorage = setupOAuth2Clients()
    root = Resource()
    root.putChild("clock", ClockPage())
    root.putChild("oauth2", OAuth2Imp(clientStorage))
    factory = Site(root)
    endpoint = endpoints.TCP4ServerEndpoint(reactor, 8880)
    endpoint.listen(factory)
    reactor.run()

if __name__ == '__main__':
    main()
