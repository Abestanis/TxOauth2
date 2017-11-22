import json

try:
    from urlparse import urlparse, parse_qs
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse, parse_qs

from twisted.web.server import NOT_DONE_YET
from txoauth2 import GrantTypes
from txoauth2.clients import PublicClient, PasswordClient
from txoauth2.errors import MalformedRequestError, MissingParameterError, \
    UnsupportedResponseTypeError, MalformedParameterError, MultipleParameterError, \
    InsecureConnectionError, ServerError, InvalidScopeError, InvalidParameterError, \
    UnauthorizedClientError, UserDeniesAuthorization, InvalidRedirectUriError
from txoauth2.imp import DictTokenStorage
from txoauth2.resource import OAuth2, InvalidDataKeyError, InsecureRedirectUriError

from tests import TwistedTestCase, MockRequest, TestTokenFactory, TestPersistentStorage, \
    TestClientStorage, getTestPasswordClient


class AbstractAuthResourceTest(TwistedTestCase):
    """ Abstract base class for test targeting the OAuth2 resource. """
    # noinspection PyTypeChecker
    _VALID_CLIENT = PasswordClient('authResourceClientId',
                                   ['https://return.nonexistent?param=retain',
                                    'http://return.nonexistent/notSecure?param=retain'],
                                   list(GrantTypes), secret='ClientSecret')
    _RESPONSE_GRANT_TYPE_MAPPING = {
        'code': GrantTypes.AuthorizationCode.value,
        'token': GrantTypes.Implicit.value
    }

    class TestOAuth2Resource(OAuth2):
        """ A test OAuth2 resource that returns the parameters given to onAuthenticate. """
        raiseErrorInOnAuthenticate = False
        UNKNOWN_SCOPE = 'unknown'

        def onAuthenticate(self, request, client, responseType, scope, redirectUri, state, dataKey):
            if self.raiseErrorInOnAuthenticate:
                self.raiseErrorInOnAuthenticate = False
                raise RuntimeError('Expected the auth resource to catch this error')
            if self.UNKNOWN_SCOPE in scope:
                return InvalidScopeError(scope, state=state)
            return request, client, responseType, scope, redirectUri, state, dataKey

    @classmethod
    def setUpClass(cls):
        super(AbstractAuthResourceTest, cls).setUpClass()
        cls._TOKEN_FACTORY = TestTokenFactory()
        cls._TOKEN_STORAGE = DictTokenStorage()
        cls._PERSISTENT_STORAGE = TestPersistentStorage()
        cls._CLIENT_STORAGE = TestClientStorage()
        cls._CLIENT_STORAGE.addClient(cls._VALID_CLIENT)
        cls._AUTH_RESOURCE = AbstractAuthResourceTest.TestOAuth2Resource(
            cls._TOKEN_FACTORY, cls._PERSISTENT_STORAGE, cls._CLIENT_STORAGE,
            authTokenStorage=cls._TOKEN_STORAGE)

    def setUp(self):
        super(AbstractAuthResourceTest, self).setUp()
        self._TOKEN_FACTORY.reset(self)

    @staticmethod
    def _createAuthRequest(**kwargs):
        """
        :param kwargs: Arguments to the request.
        :return: A GET request to the OAuth2 resource with the given arguments.
        """
        request = MockRequest('GET', 'oauth2', **kwargs)
        request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded')
        return request

    @staticmethod
    def _getParameterFromRedirectUrl(url, parameterInFragment):
        """
        :param url: The url that the resource redirected to.
        :param parameterInFragment: Whether the parameter should be in the fragment or in the query.
        :return: The parameter transmitted via the redirect url.
        """
        if not isinstance(url, str):
            url = url.decode('utf-8')
        parsedUrl = urlparse(url)
        parameter = parse_qs(parsedUrl.fragment if parameterInFragment else parsedUrl.query)
        for key, value in parameter.items():
            if len(value) == 1:
                parameter[key] = value[0]
        return parameter

    def assertRedirectsTo(self, request, redirectUri, msg):
        """
        Assert that the request redirects to the given uri and retains the query parameters.

        :param request: The request that should redirect.
        :param redirectUri: The uri where the request should redirect to.
        :param msg: The assertion message.
        :return: The actual url the request is redirecting to.
        """
        self.assertEquals(request.responseCode, 302,
                          msg=msg + ': Expected the auth token to redirect the resource owner.')
        redirectUrl = request.getResponseHeader(b'location')
        self.assertIsNotNone(
            redirectUrl, msg=msg + ': Expected the auth resource to redirect the resource owner.')
        parsedUrl = urlparse(redirectUrl)
        parsedUri = urlparse(redirectUri.encode('utf-8'))
        self.assertTrue(
            parsedUrl.scheme == parsedUri.scheme and parsedUrl.netloc == parsedUri.netloc and
            parsedUrl.path == parsedUri.path and parsedUrl.params == parsedUri.params,
            msg=msg + ': The auth token endpoint did not redirect the resource owner to the '
                      'expected url: {expected} <> {actual}'
            .format(expected=redirectUri, actual=redirectUrl))
        self.assertIn(parsedUri.query, parsedUrl.query,
                      msg=msg + ': Expected the redirect uri to contain the query parameters '
                                'of the original redirect uri of the client.')
        return redirectUrl

    def assertFailedRequest(self, request, result, expectedError, msg=None, redirectUri=None,
                            parameterInFragment=False):
        """
        Assert that the request did not succeed and that
        the auth resource returned an appropriate error response.
        :param request: The request.
        :param result: The return value of the render_POST function of the token resource.
        :param expectedError: The expected error.
        :param msg: The assertion error message.
        :param redirectUri: The redirect uri of the client.
        :param parameterInFragment: If the error parameters are in the fragment of the redirect uri.
        """
        if result == NOT_DONE_YET:
            result = request.getResponse()
        if msg.endswith('.'):
            msg = msg[:-1]
        self.assertFalse(isinstance(result, tuple),
                         msg=msg + ': Expected the auth resource not to call onAuthenticate.')
        if redirectUri is not None:
            redirectUrl = self.assertRedirectsTo(request, redirectUri, msg)
            errorResult = self._getParameterFromRedirectUrl(redirectUrl, parameterInFragment)
        else:
            self.assertEquals(
                'application/json;charset=UTF-8', request.getResponseHeader('Content-Type'),
                msg='Expected the auth resource to return an error in the json format.')
            self.assertEquals('no-store', request.getResponseHeader('Cache-Control'),
                              msg='Expected the auth resource to set Cache-Control to "no-store".')
            self.assertEquals('no-cache', request.getResponseHeader('Pragma'),
                              msg='Expected the auth resource to set Pragma to "no-cache".')
            self.assertEquals(expectedError.code, request.responseCode,
                              msg='Expected the auth resource to return a response '
                                  'with the HTTP code {code}.'.format(code=expectedError.code))
            errorResult = json.loads(result.decode('utf-8'), encoding='utf-8')
        self.assertIn('error', errorResult, msg=msg + ': Missing error parameter in response.')
        self.assertEquals(errorResult['error'], expectedError.message,
                          msg=msg + ': Result contained a different error than expected.')
        self.assertIn('error_description', errorResult,
                      msg=msg + ': Missing error_description parameter in response.')
        if not (isinstance(expectedError.detail, str) or isinstance(expectedError.detail, bytes)):
            self.assertEquals(
                errorResult['error_description'], expectedError.detail.encode('utf-8'),
                msg=msg + ': Result contained a different error description than expected.')
        else:
            self.assertEquals(
                errorResult['error_description'], expectedError.detail,
                msg=msg + ': Result contained a different error description than expected.')
        if expectedError.errorUri is not None:
            self.assertIn('error_uri', errorResult,
                          msg=msg + ': Missing error_uri parameter in response.')
            self.assertEquals(errorResult['error_uri'], expectedError.errorUri,
                              msg=msg + ': Result contained an unexpected error_uri.')
        if hasattr(expectedError, 'state') and getattr(expectedError, 'state') is not None:
            self.assertIn('state', errorResult, msg=msg + ': Missing state parameter in response.')
            self.assertEquals(
                errorResult['state'], expectedError.state if isinstance(expectedError.state, str)
                else expectedError.state.decode('utf-8', errors='replace'),
                msg=msg + ': Result contained an unexpected state.')

    def assertValidAuthRequest(self, request, result, parameters, msg, expectedDataLifetime=None):
        """
        Assert that a GET request has been processed correctly
        and the expected data has been stored.

        :param request: The GET request.
        :param result: The result of render_GET and onAuthenticate.
        :param parameters: The parameters of the request.
        :param msg: The assertion error message.
        :param expectedDataLifetime: The expected lifetime of the stored data.
        """
        if msg.endswith('.'):
            msg = msg[:-1]
        self.assertFalse(
            request.finished, msg=msg + ': Expected the auth resource not to close the request.')
        self.assertIsInstance(
            result, tuple, message=msg + ': Expected the auth resource to call onAuthenticate.')
        requestParam, client, responseType, scope, redirectUri, state, dataKey = result
        self.assertIs(
            request, requestParam, msg=msg + ': Expected the auth resource to pass the request '
                                             'to onAuthenticate as the first parameter.')
        self.assertEquals(client.id, parameters['client_id'],
                          msg=msg + ': Expected the auth resource to pass the received '
                                    'client to onAuthenticate as the second parameter.')
        parameters['response_type'] = self._RESPONSE_GRANT_TYPE_MAPPING.get(
            parameters['response_type'], parameters['response_type'])
        self.assertEquals(responseType, parameters['response_type'],
                          msg=msg + ': Expected the auth resource to pass the response '
                                    'type to onAuthenticate as the third parameter.')
        parameters['scope'] = parameters['scope'].split(' ')
        self.assertListEqual(scope, parameters['scope'],
                             msg=msg + ': Expected the auth resource to pass the scope '
                                       'to onAuthenticate as the fourth parameter.')
        expectedRedirectUri = parameters['redirect_uri'] if parameters['redirect_uri'] is not None\
            else self._VALID_CLIENT.redirectUris[0]
        self.assertEquals(redirectUri, expectedRedirectUri,
                          msg=msg + ': Expected the auth resource to pass the redirect '
                                    'uri to onAuthenticate as the fifth parameter.')
        if expectedDataLifetime is None:
            expectedDataLifetime = self._AUTH_RESOURCE.requestDataLifetime
        try:
            self.assertEquals(expectedDataLifetime, self._PERSISTENT_STORAGE.getExpireTime(dataKey),
                              msg=msg + ': Expected the auth resource to store '
                                        'the request data with the given lifetime.')
            data = self._PERSISTENT_STORAGE.pop(dataKey)
        except KeyError:
            self.fail(msg=msg + ': Expected the auth resource to pass a valid '
                                'data key to onAuthenticate as the sixth parameter.')
        for key, value in parameters.items():
            self.assertIn(key, data, msg=msg + ': Expected the data stored by auth token resource '
                                               'to contain the {name} parameter.'.format(name=key))
            self.assertEquals(value, data[key],
                              msg=msg + ': Expected the auth token resource to store the value '
                                        'of the {name} parameter.'.format(name=key))


class AbstractSharedGrantTest(AbstractAuthResourceTest):
    """
    This test contains test for shared functionality for
    the grant types that use the authentication resource.
    """
    _RESPONSE_TYPE = None

    def assertValidCodeResponse(self, request, result, data, msg,
                                expectedAdditionalData=None, expectedScope=None):
        """
        Validate the parameters of the uri that the authorization endpoint redirected to.

        :param request: The request.
        :param result: The result of the grantAccess call.
        :param data: The data that was stored in the persistent storage.
        :param msg: The assertion message.
        :param expectedAdditionalData: Expected additional data stored alongside the code.
        :param expectedScope: The expected scope of the code.
        """
        raise NotImplementedError()

    def assertFailedRequest(self, request, result, expectedError, msg=None, redirectUri=None,
                            parameterInFragment=None):
        """
        Assert that the request did not succeed and that
        the auth resource returned an appropriate error response.
        :param request: The request.
        :param result: The return value of the render_POST function of the token resource.
        :param expectedError: The expected error.
        :param msg: The assertion error message.
        :param redirectUri: The redirect uri of the client.
        :param parameterInFragment: If the error parameters are in the fragment of the redirect uri.
                                    If None, use the default for the response type.
        """
        if parameterInFragment is None:
            parameterInFragment = self._RESPONSE_TYPE == 'token'
        super(AbstractSharedGrantTest, self).assertFailedRequest(
            request, result, expectedError, msg, redirectUri, parameterInFragment)

    def testWithUnauthorizedClient(self):
        """
        Test the rejection of a request with a client
        that is not allowed to use the response type.
        """
        state = b'state\xFF\xFF'
        client = getTestPasswordClient(authorizedGrantTypes=[])
        redirectUri = client.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': client.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        self._CLIENT_STORAGE.addClient(client)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, UnauthorizedClientError(self._RESPONSE_TYPE, state=state),
            msg='Expected the auth resource to reject a request for a client that is not '
                'authorized to request an authorization using the {type} method.'
                .format(type=self._RESPONSE_TYPE), redirectUri=redirectUri)

    def testWithoutClientId(self):
        """ Test the rejection of a request without a client id. """
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MissingParameterError('client_id'),
            msg='Expected the auth resource to reject a request without a client id.')

    def testWithInvalidClientId(self):
        """ Test the rejection of a request with an invalid client id. """
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': 'invalidClientId',
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InvalidParameterError('client_id'),
            msg='Expected the auth resource to reject a request with an invalid client id.')

    def testWithMalformedClientId(self):
        """ Test the rejection of a request with a malformed client id. """
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': b'malformedClientId\xFF\xFF',
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MalformedParameterError('client_id'),
            msg='Expected the auth resource to reject a request with a malformed client id.')

    def testWithMultipleClientIds(self):
        """ Test the rejection of a request with multiple client ids. """
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': [self._VALID_CLIENT.id] * 2,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MultipleParameterError('client_id'),
            msg='Expected the auth resource to reject a request with multiple client ids.')

    def testWithoutRedirectUriButClientHasOne(self):
        """
        Test that a request without a redirect uri is accepted
        if the client has ony one predefined redirect uri.
        """
        client = PublicClient(
            'clientWithOneRedirectUri', self._VALID_CLIENT.redirectUris[:1],
            [GrantTypes.AuthorizationCode.value, GrantTypes.Implicit.value])
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': client.id,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        }
        self._CLIENT_STORAGE.addClient(client)
        request = self._createAuthRequest(arguments=parameter)
        result = self._AUTH_RESOURCE.render_GET(request)
        parameter['redirect_uri'] = None
        self.assertValidAuthRequest(request, result, parameter,
                                    msg='Expected the auth resource to accept a request '
                                        'without a redirect uri if the client has one.')

    def testWithoutRedirectUriButClientHasMultiple(self):
        """
        Test the rejection of a request without a redirect uri
        if the client has more than one predefined redirect uri.
        """
        client = PublicClient('clientWithMultipleRedirectUris', ['https://return.nonexistent'] * 2,
                              ['authorization_code'])
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': client.id,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        self._CLIENT_STORAGE.addClient(client)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MissingParameterError('redirect_uri'),
            msg='Expected the auth resource to reject a request without a redirect uri.')

    def testWithInvalidRedirectUri(self):
        """ Test the rejection of a request with an invalid redirect uri. """
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': 'invalidRedirectUri',
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InvalidRedirectUriError(),
            msg='Expected the auth resource to reject a request with an invalid redirect uri.')

    def testWithMalformedRedirectUri(self):
        """ Test the rejection of a request with a malformed redirect uri. """
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': b'malformedRedirectUri\xFF\xFF',
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MalformedParameterError('redirect_uri'),
            msg='Expected the auth resource to reject a request with a malformed redirect uri.')

    def testWithMultipleRedirectUris(self):
        """ Test the rejection of a request with multiple redirect uris. """
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': [self._VALID_CLIENT.redirectUris[0]] * 2,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MultipleParameterError('redirect_uri'),
            msg='Expected the auth resource to reject a request with multiple redirect uris.')

    def testWithoutScope(self):
        """ Test that a request without a scope is accepted if a default scope is defined. """
        defaultScope = 'default'
        authToken = AbstractAuthResourceTest.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            defaultScope=[defaultScope], authTokenStorage=self._TOKEN_STORAGE)
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'state': b'state\xFF\xFF'
        }
        request = self._createAuthRequest(arguments=parameter)
        result = authToken.render_GET(request)
        parameter['scope'] = defaultScope
        self.assertValidAuthRequest(request, result, parameter,
                                    msg='Expected the auth resource to accept a request without '
                                        'a scope if the auth resource has a valid scope.')

    def testWithoutScopeNoDefault(self):
        """ Test the rejection of a request without a scope if no default scope is defined. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MissingParameterError('scope', state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to reject a request without a scope.')

    def testWithMalformedScope(self):
        """ Test the rejection of a request with a malformed scope. """
        state = b'state\xFF\xFF'
        scope = b'malformedScope\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': scope,
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InvalidScopeError(scope, state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to reject a request with a malformed scope.')

    def testWithMultipleScopes(self):
        """ Test the rejection of a request with multiple scopes. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': ['scope1', 'scope2'],
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MultipleParameterError('scope', state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to reject a request with a multiple scopes.')

    def testWithoutState(self):
        """ Test that a request without a state is accepted. """
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All'
        }
        request = self._createAuthRequest(arguments=parameter)
        result = self._AUTH_RESOURCE.render_GET(request)
        parameter['state'] = None
        self.assertValidAuthRequest(
            request, result, parameter,
            msg='Expected the auth resource to accept a request without a state.')

    def testWithState(self):
        """ Test that a request with a state is accepted. """
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'someState'
        }
        request = self._createAuthRequest(arguments=parameter)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameter,
            msg='Expected the auth resource to accept a request with a state.')

    def testWithNonUnicodeState(self):
        """ Test that a request with a non unicode state is accepted. """
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'someStateNotUnicode\xFF\xFF'
        }
        request = self._createAuthRequest(arguments=parameter)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameter,
            msg='Expected the auth resource to accept a request with a non unicode state.')

    def testWhenDisabled(self):
        """ Test the rejection of a request when the return type is disabled. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        authResource = AbstractAuthResourceTest.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE, grantTypes=[])
        result = authResource.render_GET(request)
        self.assertFailedRequest(
            request, result, UnsupportedResponseTypeError(self._RESPONSE_TYPE, state),
            msg='Expected the auth resource to reject a request for the {type} response type '
                'if it is not enabled.'.format(type=self._RESPONSE_TYPE), redirectUri=redirectUri)

    def testDataLifetime(self):
        """
        Test that the lifetime of the data stored by render_GET
        is controlled by the requestDataLifeTime parameter.
        """
        lifetime = 10
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        }
        request = self._createAuthRequest(arguments=parameter)
        authResource = AbstractAuthResourceTest.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            requestDataLifeTime=lifetime, authTokenStorage=self._TOKEN_STORAGE)
        result = authResource.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameter,
            msg='Expected the auth resource to accept a request without a redirect uri '
                'if the client has one.', expectedDataLifetime=lifetime)

    def testDenyAccess(self):
        """ Test that denyAccess redirects with the expected error. """
        dataKey = 'userDenies_' + self._RESPONSE_TYPE
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        self._PERSISTENT_STORAGE.put(dataKey, {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': 'All',
            'state': state
        })
        request = MockRequest('GET', 'some/path')
        result = self._AUTH_RESOURCE.denyAccess(request, dataKey)
        self.assertFailedRequest(
            request, result, UserDeniesAuthorization(state), redirectUri=redirectUri,
            msg='Expected denyAccess to redirect the resource owner to the '
                'redirection endpoint with an access denied error.')

    def testGrantAccessInsecureRedirectUri(self):
        """ Test that grandAccess raises InsecureRedirectUriError for an insecure redirect uri. """
        dataKey = 'insecureRedirectUriDataKey' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[1]
        self.assertTrue(redirectUri.startswith('http://'), msg='The redirect uri is not insecure.')
        request = MockRequest('GET', 'some/path')
        self._PERSISTENT_STORAGE.put(dataKey, {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        self.assertRaises(InsecureRedirectUriError, self._AUTH_RESOURCE.grantAccess,
                          request, dataKey)
        try:
            self.assertEquals(self._AUTH_RESOURCE.requestDataLifetime,
                              self._PERSISTENT_STORAGE.getExpireTime(dataKey),
                              msg='Expected the data to be stored with the expected lifetime.')
            self._PERSISTENT_STORAGE.pop(dataKey)
        except KeyError:
            self.fail('Expected the data to still be in the persistent storage.')

    def testGrantAccessInsecureConnection(self):
        """
        Test that grandAccess returns the expected error for a request over an insecure transport.
        """
        dataKey = 'insecureConnectionDataKey' + self._RESPONSE_TYPE
        request = MockRequest('GET', 'some/path', isSecure=False)
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        self._PERSISTENT_STORAGE.put(dataKey, {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': 'All',
            'state': state
        })
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey)
        self.assertFailedRequest(
            request, result, InsecureConnectionError(state), redirectUri=redirectUri,
            msg='Expected the authorization resource to '
                'reject a request over an insecure transport.')

    def testGrantAccessInvalidScope(self):
        """ Test that grandAccess rejects a call with a scope that is not in the original scope. """
        dataKey = 'dataKeyInvalidScope' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path')
        state = b'state\xFF\xFF'
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': state
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        scope = ['Other']
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey, scope=scope)
        self.assertFailedRequest(
            request, result, InvalidScopeError(scope, state), redirectUri=redirectUri,
            msg='Expected grantAccess to reject an invalid scope.')

    def testGrantAccess(self):
        """ Test that grandAccess redirects with the expected parameters. """
        dataKey = 'dataKey' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path')
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': b'state\xFF\xFF'
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey)
        self.assertValidCodeResponse(
            request, result, data,
            msg='Expected the auth resource to correctly handle a valid accepted {type} grant.'
                .format(type=self._RESPONSE_TYPE))

    def testGrantAccessInsecureRedirectUriAllowed(self):
        """
        Test that grandAccess accepts a call with an insecure
        redirect uri if it is allowed.
        """
        dataKey = 'insecureRedirectUriDataKey' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[1]
        self.assertTrue(redirectUri.startswith('http://'), msg='The redirect uri is not insecure.')
        request = MockRequest('GET', 'some/path')
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': b'state\xFF\xFF'
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey, allowInsecureRedirectUri=True)
        self.assertValidCodeResponse(
            request, result, data,
            msg='Expected the auth resource to correctly handle a valid accepted {type} grant '
                'with an insecure redirect uri, if it is allowed.'.format(type=self._RESPONSE_TYPE))

    def testGrantAccessInsecureConnectionAllowed(self):
        """
        Test that grandAccess accepts a call with a
        request over an insecure transport if it is allowed.
        """
        dataKey = 'insecureConnectionDataKey' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path', isSecure=False)
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': b'state\xFF\xFF'
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        authResource = AbstractAuthResourceTest.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            authTokenStorage=self._TOKEN_STORAGE, allowInsecureRequestDebug=True)
        result = authResource.grantAccess(request, dataKey)
        self.assertValidCodeResponse(
            request, result, data,
            msg='Expected the auth resource to correctly handle a valid accepted {type} grant '
                'request over an insecure transport, if it is allowed.'
                .format(type=self._RESPONSE_TYPE))

    def testGrantAccessSubsetScope(self):
        """ Test that grandAccess accepts a call with a subset of the original scope. """
        dataKey = 'dataKeySubsetScope' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path')
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All', 'Other'],
            'state': b'state\xFF\xFF'
        }
        scope = ['Other']
        self._PERSISTENT_STORAGE.put(dataKey, data)
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey, scope=scope)
        self.assertValidCodeResponse(
            request, result, data, expectedScope=scope,
            msg='Expected the auth resource to correctly handle a valid accepted {type} grant '
                'with a subset of the scope original requested.'.format(type=self._RESPONSE_TYPE))


class AuthResourceTest(AbstractAuthResourceTest):
    """ Tests aspects of the OAuth2 resource that do not depend on the response type. """
    def testContentType(self):
        """ Test the rejection of a request with an invalid content type. """
        request = MockRequest('GET', 'oauth2', arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result,
            MalformedRequestError('The Content-Type must be "application/x-www-form-urlencoded"'),
            msg='Expected the auth resource to reject a request with an invalid content type.')

    def testWithoutResponseType(self):
        """ Test the rejection of a request without a response type. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MissingParameterError('response_type', state=state),
            redirectUri=redirectUri, msg='Expected the auth resource to reject a '
                                         'request without a response type.')

    def testWithInvalidResponseType(self):
        """ Test the rejection of a request with an invalid response type. """
        state = b'state\xFF\xFF'
        responseType = 'invalidResponseType'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': responseType,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, UnsupportedResponseTypeError(responseType, state=state),
            redirectUri=redirectUri, msg='Expected the auth resource to reject '
                                         'a request with an invalid response type.')

    def testWithMalformedResponseType(self):
        """ Test the rejection of a request with a malformed response type. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': b'malformedResponseType\xFF\xFF',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MalformedParameterError('response_type', state=state),
            redirectUri=redirectUri, msg='Expected the auth resource to reject '
                                         'a request with a malformed response type.')

    def testWithMultipleResponseTypes(self):
        """ Test the rejection of a request with multiple response types. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': ['code'] * 2,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MultipleParameterError('response_type', state=state),
            redirectUri=redirectUri, msg='Expected the auth resource to reject '
                                         'a request with multiple response types.')

    def testInsecureConnection(self):
        """ Test the rejection of a request over an insecure transport. """
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        parameters = {
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        }
        request = self._createAuthRequest(arguments=parameters, isSecure=False)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InsecureConnectionError(), redirectUri=redirectUri,
            msg='Expected the auth resource to reject a request over an insecure transport.')
        authResource = self.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            allowInsecureRequestDebug=True, authTokenStorage=self._TOKEN_STORAGE)
        request = self._createAuthRequest(arguments=parameters, isSecure=False)
        result = authResource.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameters,
            msg='Expected the auth resource to accept a request over an '
                'insecure transport if allowInsecureRequestDebug is true.')

    def testErrorInOnAuthenticate(self):
        """ Test that an error in onAuthenticate is caught and a ServerError is returned. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        self._AUTH_RESOURCE.raiseErrorInOnAuthenticate = True
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, ServerError(state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to catch errors thrown in the onAuthenticate method.')

    def testSendsErrorInOnAuthenticate(self):
        """ Test tat any AuthorizationErrors returned by onAuthenticate are handled. """
        state = b'state\xFF\xFF'
        scope = self._AUTH_RESOURCE.UNKNOWN_SCOPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self._createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': scope,
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InvalidScopeError(scope, state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to send the error '
                'returned from the onAuthenticate method.')

    def testGrantAccessDataKeyExpired(self):
        """ Test that grantAccess raises InvalidDataKeyError for an invalid data key. """
        request = MockRequest('GET', 'some/path')
        self.assertRaises(InvalidDataKeyError, self._AUTH_RESOURCE.grantAccess,
                          request, 'invalidDataKey')

    def testDenyAccessDataKeyExpired(self):
        """ Test that denyAccess raises InvalidDataKeyError for an invalid data key. """
        request = MockRequest('GET', 'some/path')
        self.assertRaises(InvalidDataKeyError, self._AUTH_RESOURCE.denyAccess,
                          request, 'invalidDataKey')

    def testCustomResponseType(self):
        """ Test that a request with a custom response type is accepted. """
        responseType = 'myCustomResponseType'
        state = b'state\xFF\xFF'
        client = PasswordClient('customResponseTypeClient', ['https://redirect.noexistent'],
                                [responseType], 'clientSecret')
        parameters = {
            'response_type': responseType,
            'client_id': client.id,
            'redirect_uri': client.redirectUris[0],
            'scope': 'All',
            'state': state
        }
        request = self._createAuthRequest(arguments=parameters)
        self._CLIENT_STORAGE.addClient(client)
        authResource = self.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            authTokenStorage=self._TOKEN_STORAGE, grantTypes=[responseType])
        result = authResource.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameters, msg='Expected the authorization token resource to accept '
                                             'a valid request with a custom response type.')

    def testCustomResponseTypeUnauthorizedClient(self):
        """
        Test that a request with a custom response type is rejected
        if the client is not authorized to use that response type.
        """
        responseType = 'myCustomResponseType'
        state = b'state\xFF\xFF'
        client = PasswordClient('customResponseTypeClientUnauthorized',
                                ['https://redirect.noexistent'], [], 'clientSecret')
        redirectUri = client.redirectUris[0]
        parameters = {
            'response_type': responseType,
            'client_id': client.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        }
        request = self._createAuthRequest(arguments=parameters)
        self._CLIENT_STORAGE.addClient(client)
        authResource = self.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            authTokenStorage=self._TOKEN_STORAGE, grantTypes=[responseType])
        result = authResource.render_GET(request)
        self.assertFailedRequest(
            request, result, UnauthorizedClientError(responseType, state), redirectUri=redirectUri,
            msg='Expected the authorization token resource to reject a request with a '
                'custom response type that the client is not allowed to use.')

    def testCustomResponseTypeNotAllowed(self):
        """ Test that a request with a custom response type is rejected if it is not enabled. """
        responseType = 'myCustomResponseType'
        state = b'state\xFF\xFF'
        client = PasswordClient('customResponseTypeClientNotAllowed',
                                ['https://redirect.noexistent'], [responseType], 'clientSecret')
        redirectUri = client.redirectUris[0]
        parameters = {
            'response_type': responseType,
            'client_id': client.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        }
        request = self._createAuthRequest(arguments=parameters)
        self._CLIENT_STORAGE.addClient(client)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, UnsupportedResponseTypeError(responseType, state),
            redirectUri=redirectUri, msg='Expected the authorization token resource to reject a '
                                         'request with a custom response type that is not allowed.')

    def testGrantAccessCustomResponseType(self):
        """ Test that grantAccess rejects a call for a request with a custom response type. """
        responseType = 'myCustomResponseType'
        state = b'state\xFF\xFF'
        client = PasswordClient('customResponseTypeClientGrantAccess',
                                ['https://redirect.noexistent'], [responseType], 'clientSecret')
        dataKey = 'customResponseTypeDataKey'
        self._PERSISTENT_STORAGE.put(dataKey, {
            'response_type': responseType,
            'client_id': client.id,
            'redirect_uri': client.redirectUris[0],
            'scope': 'All',
            'state': state
        })
        request = MockRequest('GET', 'some/path')
        self._CLIENT_STORAGE.addClient(client)
        self.assertRaises(ValueError, self._AUTH_RESOURCE.grantAccess, request, dataKey)
        try:
            self.assertEquals(self._AUTH_RESOURCE.requestDataLifetime,
                              self._PERSISTENT_STORAGE.getExpireTime(dataKey),
                              msg='Expected the data to be stored with the expected lifetime.')
            self._PERSISTENT_STORAGE.pop(dataKey)
        except KeyError:
            self.fail('Expected the data to still be in the persistent storage.')
