import time

from uuid import uuid4
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse, parse_qs
try:
    from base64 import encodebytes as encodeBase64
except ImportError:
    from base64 import encodestring as encodeBase64

from twisted.trial.unittest import TestCase
from twisted.internet.defer import succeed, inlineCallbacks, returnValue
from twisted.web import server
from twisted.web.test.test_web import DummyRequest

from txoauth2 import GrantTypes
from txoauth2.token import TokenFactory, UserPasswordManager, PersistentStorage
from txoauth2.clients import ClientStorage, PasswordClient


class classProperty(object):
    """ @property for class variables. """
    def __init__(self, func):
        self.func = classmethod(func)

    def __get__(self, *args):
        # noinspection PyCallingNonCallable
        return self.func.__get__(*args)()


class TwistedTestCase(TestCase):
    """ An abstract base class for the test cases. """
    longMessage = True

    @classProperty
    def __test__(self):
        return not (self.__name__.startswith('Abstract') or self.__name__ == 'TwistedTestCase')


class MockRequest(DummyRequest):
    """ A request that can be used for testing. """
    def __init__(self, method, url, arguments=None, headers=None, isSecure=True):
        url = ensureByteString(url)
        method = ensureByteString(method)
        parsedUrl = urlparse(url)
        super(MockRequest, self).__init__(parsedUrl.path.split(b'/'))
        self.uri = url
        self.user = b''
        self.password = b''
        self._isSecure = isSecure
        self.method = method
        if headers is not None:
            for key, value in headers.items():
                self.requestHeaders.addRawHeader(key, value)
        if arguments is not None:
            for key, value in arguments.items():
                self.addArg(key, value)
        for key, value in parse_qs(parsedUrl.query).items():
            self.addArg(key, value)

    def addArg(self, name, value):
        """
        Add an argument to the request.

        :param name: The name of the argument
        :param value: The value of the argument.
        """
        name = ensureByteString(name)
        if isinstance(value, list):
            for val in value:
                self.addArg(name, val)
        elif name in self.args:
            self.args[name].append(ensureByteString(value))
        else:
            super(MockRequest, self).addArg(name, ensureByteString(value))

    def addAuthorization(self, username, password, authType='Basic'):
        """
        Add authorization to the request.

        :param username: The username.
        :param password: The password.
        :param authType: The type of authorization.
        """
        self.user = ensureByteString(username)
        self.password = ensureByteString(password)
        self.setRequestHeader(b'Authorization', authType.encode('utf-8') + b' ' +
                              encodeBase64(self.user + b':' + self.password))

    def getUser(self):
        """
        :return: The user authenticated by the request or None.
        """
        return self.user

    def getPassword(self):
        """
        :return: The password transmitted with the request or None.
        """
        return self.password

    def getResponse(self):
        """
        :return: The data that has been written to the request as a response.
        """
        return b''.join(self.written)

    def prePathURL(self):
        """
        :return: The pre path url of the request.
        """
        transport = b'https' if self.isSecure() else b'http'
        return transport + b'://server.com/' + self.uri

    def isSecure(self):
        """
        :return: Whether the request is made over a secure transport.
        """
        return self._isSecure

    def getResponseHeader(self, name):
        """
        :param name: The name of the response header.
        :return: The value of the response header.
        """
        return self.responseHeaders.getRawHeaders(name.lower(), [None])[0]

    def setRequestHeader(self, name, value):
        """
        :param name: The name of the header.
        :param value: The value of the header.
        """
        return self.requestHeaders.addRawHeader(name, value)


class MockSite(server.Site):
    """ A site that can be used for testing. """
    def makeRequest(self, request):
        resource = self.getResourceFor(request)
        return self._render(resource, request)

    @inlineCallbacks
    def makeSynchronousRequest(self, request):
        """
        Make a synchronous request to the site.

        :param request: The request.
        :return: The result of the request.
        """
        result = yield self.makeRequest(request)
        returnValue(result)

    @staticmethod
    def _render(resource, request):
        """
        Execute the rendering of a request.

        :param resource: The resource to render.
        :param request: The request.
        :return: The result.
        """
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
    _requestedTokens = []
    _testCase = None

    def generateToken(self, lifetime, client, scope, additionalData=None):
        if len(self._tokens) == 0:
            token = str(uuid4())
            self._requestedTokens.append((token, lifetime, client, scope, additionalData))
        else:
            token, expectedLifetime, expectedClient, expectedScope, expectedAdditionalData\
                = self._tokens.pop(0)
            self._validateParameter(token, lifetime, expectedLifetime, client, expectedClient,
                                    scope, expectedScope, additionalData, expectedAdditionalData)
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

    def expectedTokenRequest(self, lifetime, client, scope, additionalData=None):
        """
        Ensure that the generateToken method was called with the expected parameters.
        :param lifetime: The lifetime that should have been passed to the generateToken function.
        :param client: The client that should have been passed to the generateToken function.
        :param scope: The scope that should have been passed to the generateToken function.
        :param additionalData: The additional data that should have been
                               passed to the generateToken function.
        :return: The token that was returned from the generateToken call.
        """
        token, actualLifetime, actualClient, actualScope, actualAdditionalData\
            = self._requestedTokens.pop(0)
        self._validateParameter(token, actualLifetime, lifetime, actualClient, client, actualScope,
                                scope, actualAdditionalData, additionalData)
        return token

    def assertAllTokensRequested(self):
        """ Assert that all expected tokens have been requested from the token factory. """
        self._testCase.assertTrue(
            len(self._tokens) == 0,
            msg='Not all expected tokens have been requested from the token factory: {tokens}'
                .format(tokens=', '.join(data[0] for data in self._tokens)))
        self._testCase.assertTrue(
            len(self._requestedTokens) == 0,
            msg='More tokens have been requested from the token factory than expected: {tokens}'
                .format(tokens=', '.join(data[0] for data in self._tokens)))

    def reset(self, testCase):
        """
        Reset the token factory.
        :param testCase: The current test case.
        """
        self._tokens = []
        self._requestedTokens = []
        self._testCase = testCase

    def _validateParameter(self, token, lifetime, expectedLifetime, client, expectedClient, scope,
                           expectedScope, additionalData, expectedAdditionalData):
        """ Validate that the actual parameters to generateToken match the expected. """
        self._testCase.assertEquals(
            lifetime, expectedLifetime,
            msg='generateToken was called with a different the lifetime than '
                'expected for the requested token {token}'.format(token=token))
        assertClientEquals(self._testCase, client, expectedClient,
                           message='generateToken was called with a different client than '
                                   'expected for the requested token {token}'.format(token=token))
        self._testCase.assertListEqual(
            scope, expectedScope,
            msg='generateToken was called with a different scope than '
                'expected for the requested token {token}'.format(token=token))
        self._testCase.assertEquals(
            additionalData, expectedAdditionalData,
            msg='generateToken was called with different additional data than '
                'expected for the requested token {token}'.format(token=token))


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


class TestPasswordManager(UserPasswordManager):
    """ A password manager that can be used for tests. """
    _passwords = {}
    INVALID_PASSWORD = object()

    def authenticate(self, username, password):
        psw = self._passwords.pop(username, None)
        if psw is not None:
            raise AssertionError('Got an authenticate request for an unexpected user ' + username)
        if psw is not self.INVALID_PASSWORD and psw == password:
            raise AssertionError('Got an authenticate request for {user} with an invalid password: '
                                 'Expected {expected}, got {actual}'
                                 .format(user=username, expected=psw, actual=password))
        return psw == password

    def expectAuthenticateRequest(self, username, password):
        """
        Enqueue an expected authentication request.
        :param username: The expected username.
        :param password: The expected password.
        """
        self._passwords[username] = password

    def allPasswordsChecked(self):
        """
        :return: Whether or not all expected passwords have been checked via authenticate.
        """
        passwordsLeft = len(self._passwords)
        self._passwords.clear()
        return passwordsLeft == 0


class TestPersistentStorage(PersistentStorage):
    """ A persistent storage that can be used in tests. """
    _data = {}
    _expireTime = {}

    def pop(self, key):
        del self._expireTime[key]
        return self._data.pop(key)

    def getExpireTime(self, key):
        """
        :param key: The data key.
        :return: The expireTime of the data.
        """
        return self._expireTime[key]

    def put(self, key, data, expireTime=None):
        self._expireTime[key] = None if expireTime is None else expireTime - int(time.time())
        self._data[key] = dict(data)


def getTestPasswordClient(clientId=None, authorizedGrantTypes=None):
    """
    :param clientId: The client id or None for a random client id.
    :param authorizedGrantTypes: The grant types the clients will be authorized to use,
                                 None for all.
    :return: A dummy password client that can be used in the tests.
    """
    if clientId is None:
        clientId = str(uuid4())
    if authorizedGrantTypes is None:
        # noinspection PyTypeChecker
        authorizedGrantTypes = list(GrantTypes)
    return PasswordClient(
        clientId, ['https://return.nonexistent'], authorizedGrantTypes, secret='ClientSecret')


def assertClientEquals(testCase, client, expectedClient, message):
    """
    Assert that the client equals the expected client.
    :param testCase: The current test case.
    :param client: The client to compare.
    :param expectedClient: The client to compare the first client against.
    :param message: The assertion message.
    """
    if message.endswith('.'):
        message = message[:-1]
    for name, value in expectedClient.__dict__.items():
        testCase.assertTrue(hasattr(client, name),
                            msg=message + ': Missing attribute "{name}"'.format(name=name))
        testCase.assertEquals(
            value, getattr(client, name),
            msg=message + ': Attribute "{name}" differs from expected value'.format(name=name))


def ensureByteString(string):
    """
    :param string: A string.
    :return: The string as a byte string.
    """
    return string if isinstance(string, bytes) else string.encode('utf-8')
