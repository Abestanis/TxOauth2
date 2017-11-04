import time

from twisted.trial.unittest import TestCase
from twisted.internet.defer import succeed, inlineCallbacks, returnValue
from twisted.web import server
from twisted.web.test.test_web import DummyRequest

from oauth2.token import TokenStorage


class TwistedTestCase(TestCase):
    longMessage = True


class MockRequest(DummyRequest):
    def __init__(self, method, url, args=None, headers=None, isSecure=True):
        super(MockRequest, self).__init__(url.split('/'))
        self._url = url
        self._isSecure = isSecure
        self.method = method
        if headers is not None:
            for key, value in headers.items():
                self.requestHeaders.addRawHeader(key, value)
        if args is not None:
            for key, value in args.items():
                self.addArg(key, value)

    def getResponse(self):
        return b''.join(self.written)

    def prePathURL(self):
        return 'http://server.com/' + self._url

    def isSecure(self):
        return self._isSecure

    def getResponseHeader(self, name):
        return self.responseHeaders.getRawHeaders(name.lower(), [None])[0]

    def setRequestHeader(self, name, value):
        return self.requestHeaders.addRawHeader(name, value)


class MockSite(server.Site):
    def makeRequest(self, request):
        resource = self.getResourceFor(request)
        return self._render(resource, request)

    @inlineCallbacks
    def makeSynchronousRequest(self, request):
        result = yield self.makeRequest(request)
        returnValue(result)

    @staticmethod
    def _render(resource, request):
        result = resource.render(request)
        if isinstance(result, bytes):
            request.write(result)
            request.finish()
            return succeed(None)
        elif result is server.NOT_DONE_YET:
            if request.finished:
                return succeed(result)
            else:
                return request.notifyFinish()
        else:
            raise ValueError("Unexpected return value: {result!r}".format(result=result))


class MockTokenStorage(TokenStorage):
    _tokens = {}

    def contains(self, token):
        return token in self._tokens

    def hasAccess(self, token, scope):
        if token not in self._tokens:
            return False
        expireTime = self._tokens[token]['expireTime']
        if expireTime is not None and time.time() > expireTime:
            del self._tokens[token]
            return False
        for scopeItem in scope:
            if scopeItem not in self._tokens[token]['scope']:
                return False
        return True

    def getTokenData(self, token):
        return self._tokens[token]['data']

    def store(self, token, client, scope, additionalData=None, expireTime=None):
        self._tokens[token] = {
            'data': additionalData,
            'expireTime': expireTime,
            'scope': scope
        }
