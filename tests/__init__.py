from urlparse import urlparse, parse_qs

from twisted.trial.unittest import TestCase
from twisted.internet.defer import succeed, inlineCallbacks, returnValue
from twisted.web import server
from twisted.web.test.test_web import DummyRequest


class TwistedTestCase(TestCase):
    longMessage = True


class MockRequest(DummyRequest):
    def __init__(self, method, url, arguments=None, headers=None, isSecure=True):
        parsedUrl = urlparse(url)
        super(MockRequest, self).__init__(parsedUrl.path.split('/'))
        self._url = url
        self._isSecure = isSecure
        self.method = method
        if headers is not None:
            for key, value in headers.items():
                self.requestHeaders.addRawHeader(key, value)
        if arguments is not None:
            for key, value in arguments.items():
                self.addArg(key, value)
        for key, value in parse_qs(parsedUrl.query):
            self.addArg(key, value)

    def getResponse(self):
        return b''.join(self.written)

    def prePathURL(self):
        transport = 'https' if self.isSecure() else 'http'
        return transport + '://server.com/' + self._url

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
