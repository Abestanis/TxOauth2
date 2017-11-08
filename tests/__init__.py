from txoauth2.clients import Client

try:
    from urlparse import urlparse, parse_qs
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse, parse_qs

from twisted.trial.unittest import TestCase
from twisted.internet.defer import succeed, inlineCallbacks, returnValue
from twisted.web import server
from twisted.web.test.test_web import DummyRequest


class AbstractTestCase(type):
    """ Metaclass that prevents abstract tests classes from being executed. """
    def __getattribute__(self, name):
        if '__test__' == name:
            return not (self.__name__.startswith('Abstract') or self.__name__ == 'TwistedTestCase')
        return super(AbstractTestCase, self).__getattribute__(name)


class TwistedTestCase(TestCase):
    __metaclass__ = AbstractTestCase
    longMessage = True


class MockRequest(DummyRequest):
    def __init__(self, method, url, arguments=None, headers=None, isSecure=True):
        url = _ensureByteString(url)
        method = _ensureByteString(method)
        parsedUrl = urlparse(url)
        super(MockRequest, self).__init__(parsedUrl.path.split(b'/'))
        self.uri = url
        self._isSecure = isSecure
        self.method = method
        if headers is not None:
            for key, value in headers.items():
                self.requestHeaders.addRawHeader(key, value)
        if arguments is not None:
            for key, value in arguments.items():
                self.addArg(_ensureByteString(key), _ensureByteString(value))
        for key, value in parse_qs(parsedUrl.query).items():
            self.addArg(key, value)

    def getResponse(self):
        return b''.join(self.written)

    def prePathURL(self):
        transport = b'https' if self.isSecure() else b'http'
        return transport + b'://server.com/' + self.uri

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


def getDummyClient():
    """
    :return: A dummy client that can be used in the tests.
    """
    client = Client()
    client.clientId = 'ClientId'
    client.clientSecret = 'ClientSecret'
    client.name = 'ClientName'
    client.redirectUris = ['https://return.nonexistent']
    return client


def assertClientEquals(testCase, client, expectedClient, msg):
    """
    Assert that the client equals the expected client.
    :param testCase: The current test case.
    :param client: The client to compare.
    :param expectedClient: The client to compare the first client against.
    :param msg: The assertion message.
    """
    testCase.assertEquals(client.clientId, expectedClient.clientId,
                          msg=msg + ': The client id differs.')
    testCase.assertEquals(client.clientSecret, expectedClient.clientSecret,
                          msg=msg + ': The client secret differs.')
    testCase.assertEquals(client.redirectUris, expectedClient.redirectUris,
                          msg=msg + ': The redirect uris are not the same.')
    testCase.assertEquals(client.name, expectedClient.name,
                          msg=msg + ': The client name differs.')


def _ensureByteString(string):
    """
    :param string: A string.
    :return: The string as a byte string.
    """
    return string if isinstance(string, bytes) else string.encode('utf-8')
