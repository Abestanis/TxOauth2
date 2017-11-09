try:
    from urlparse import urlparse, parse_qs
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse, parse_qs

from twisted.trial.unittest import TestCase
from twisted.internet.defer import succeed, inlineCallbacks, returnValue
from twisted.web import server
from twisted.web.test.test_web import DummyRequest

from txoauth2.token import TokenFactory
from txoauth2.clients import Client, ClientStorage, ClientAuthType


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

    def addArg(self, name, value):
        if isinstance(value, list):
            for val in value:
                self.addArg(name, val)
        elif name in self.args:
            self.args[name].append(value)
        else:
            super(MockRequest, self).addArg(name, value)

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


class TestTokenFactory(TokenFactory):
    """ A token factory that can be used for tests. """
    _tokens = []
    _testCase = None

    def generateToken(self, lifetime, client, scope, additionalData=None):
        token, expectedLifetime, expectedClient, expectedScope, expectedAdditionalData\
            = self._tokens.pop(0)
        self._testCase.assertEquals(
            lifetime, expectedLifetime,
            msg='generateToken was called with a different the lifetime than '
                'expected for the requested token {token}'.format(token=token))
        assertClientEquals(self._testCase, client, expectedClient,
                           msg='generateToken was called with a different client than '
                               'expected for the requested token {token}'.format(token=token))
        self._testCase.assertListEqual(
            scope, expectedScope,
            msg='generateToken was called with a different scope than '
                'expected for the requested token {token}'.format(token=token))
        self._testCase.assertEquals(
            additionalData, expectedAdditionalData,
            msg='generateToken was called with different additional data than '
                'expected for the requested token {token}'.format(token=token))
        return token

    def expectTokenRequest(self, token, lifetime, client, scope, additionalData=None):
        """
        Enqueue a token and its expected parameters.
        The token is returned by the generateToken method after it has checked
        that it was called with the same parameters that are supplied to this call.
        Tokens are used in the order they are expected.
        :param token: The token that should get returned from the expected generateToken call.
        :param lifetime: The lifetime that should get passed to the generateToken function.
        :param client: The client that should get passed to the generateToken function.
        :param scope: The scope that should get passed to the generateToken function.
        :param additionalData: The additional data that should get
                               passed to the generateToken function.
        """
        self._tokens.append((token, lifetime, client, scope, additionalData))

    def assertAllTokensRequested(self):
        """ Assert that all expected tokens have been requested from the token factory. """
        self._testCase.assertTrue(
            len(self._tokens) == 0,
            msg='Not all expected tokens have been requested from the token factory: {tokens}'
                .format(tokens=', '.join(data[0] for data in self._tokens)))

    def reset(self, testCase):
        """
        Reset the token factory.
        :param testCase: The current test case.
        """
        self._tokens = []
        self._testCase = testCase


class TestClientStorage(ClientStorage):
    """ A client storage that can be used for tests. """
    _clients = {}

    def addClient(self, client):
        """
        Add a new client to the storage.
        :param client: The new client.
        """
        self._clients[client.id] = client

    def getClient(self, clientId):
        return self._clients[clientId]


def getDummyClient():
    """
    :return: A dummy client that can be used in the tests.
    """
    return Client('ClientId', ['https://return.nonexistent'], ClientAuthType.SECRET, 'ClientSecret')


def assertClientEquals(testCase, client, expectedClient, msg):
    """
    Assert that the client equals the expected client.
    :param testCase: The current test case.
    :param client: The client to compare.
    :param expectedClient: The client to compare the first client against.
    :param msg: The assertion message.
    """
    testCase.assertEquals(client.id, expectedClient.id,
                          msg=msg + ': The client id differs.')
    testCase.assertIs(client.authType, expectedClient.authType,
                      msg=msg + ': The client authentication type differs.')
    testCase.assertEquals(client.authToken, expectedClient.authToken,
                          msg=msg + ': The client authentication token differs.')
    testCase.assertEquals(client.redirectUris, expectedClient.redirectUris,
                          msg=msg + ': The redirect uris are not the same.')


def _ensureByteString(string):
    """
    :param string: A string.
    :return: The string as a byte string.
    """
    return string if isinstance(string, bytes) else string.encode('utf-8')
