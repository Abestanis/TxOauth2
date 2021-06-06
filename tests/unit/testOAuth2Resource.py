""" Tests for the authorization resource. """

import json
import warnings

try:
    from urlparse import urlparse, parse_qs
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse, parse_qs

from twisted.web.server import NOT_DONE_YET
from txoauth2 import GrantTypes
from txoauth2.clients import PasswordClient
from txoauth2.errors import MissingParameterError, UnauthorizedClientError, \
    UnsupportedResponseTypeError, MalformedParameterError, MultipleParameterError, \
    InsecureConnectionError, ServerError, InvalidScopeError, InvalidTokenError, \
    TemporarilyUnavailableError
from txoauth2.imp import DictTokenStorage
from txoauth2.resource import OAuth2, InvalidDataKeyError

from tests import TwistedTestCase, MockRequest, TestTokenFactory, TestPersistentStorage, \
    TestClientStorage


class AbstractAuthResourceTest(TwistedTestCase):
    """ Abstract base class for test targeting the OAuth2 resource. """
    # noinspection HttpUrlsUsage
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
        UNKNOWN_SCOPE_RETURN = 'unknown_return'
        UNKNOWN_SCOPE_RAISING_OAUTH2_ERROR = 'unknown_raise_oauth2_error'
        TEMPORARY_UNAVAILABLE_SCOPE = 'temporary_unavailable'
        ERROR_MESSAGE = 'Expected the auth resource to catch this error'

        def onAuthenticate(self, request, client, responseType, scope, redirectUri, state, dataKey):
            if self.raiseErrorInOnAuthenticate:
                self.raiseErrorInOnAuthenticate = False
                raise RuntimeError(self.ERROR_MESSAGE)
            if self.UNKNOWN_SCOPE in scope:
                raise InvalidScopeError(scope, state=state)
            if self.UNKNOWN_SCOPE_RETURN in scope:
                return InvalidScopeError(scope, state=state)
            if self.UNKNOWN_SCOPE_RAISING_OAUTH2_ERROR in scope:
                raise InvalidTokenError(self.ERROR_MESSAGE)
            if self.TEMPORARY_UNAVAILABLE_SCOPE in scope:
                raise TemporarilyUnavailableError(state=state)
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
    def createAuthRequest(**kwargs):
        """
        :param kwargs: Arguments to the request.
        :return: A GET request to the OAuth2 resource with the given arguments.
        """
        return MockRequest('GET', 'oauth2', **kwargs)

    @staticmethod
    def getParameterFromRedirectUrl(url, parameterInFragment):
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
        self.assertEqual(302, request.responseCode,
                         msg=msg + ': Expected the auth resource to redirect the resource owner.')
        redirectUrl = request.getResponseHeader(b'location')
        self.assertIsNotNone(
            redirectUrl, msg=msg + ': Expected the auth resource to redirect the resource owner.')
        parsedUrl = urlparse(redirectUrl)
        parsedUri = urlparse(redirectUri.encode('utf-8'))
        self.assertTrue(
            parsedUrl.scheme == parsedUri.scheme and parsedUrl.netloc == parsedUri.netloc and
            parsedUrl.path == parsedUri.path and parsedUrl.params == parsedUri.params,
            msg='{msg}: The auth token endpoint did not redirect '
                'the resource owner to the expected url: '
                '{expected} <> {actual}'.format(msg=msg, expected=redirectUri, actual=redirectUrl))
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
            errorResult = self.getParameterFromRedirectUrl(redirectUrl, parameterInFragment)
        else:
            self.assertEqual(
                'application/json;charset=UTF-8', request.getResponseHeader('Content-Type'),
                msg='Expected the auth resource to return an error in the json format.')
            self.assertEqual('no-store', request.getResponseHeader('Cache-Control'),
                             msg='Expected the auth resource to set Cache-Control to "no-store".')
            self.assertEqual('no-cache', request.getResponseHeader('Pragma'),
                             msg='Expected the auth resource to set Pragma to "no-cache".')
            self.assertEqual(expectedError.code, request.responseCode,
                             msg='Expected the auth resource to return a response '
                                 'with the HTTP code {code}.'.format(code=expectedError.code))
            errorResult = json.loads(result.decode('utf-8'), encoding='utf-8')
        self.assertIn('error', errorResult, msg=msg + ': Missing error parameter in response.')
        self.assertEqual(expectedError.name, errorResult['error'],
                         msg=msg + ': Result contained a different error than expected.')
        self.assertIn('error_description', errorResult,
                      msg=msg + ': Missing error_description parameter in response.')
        if not isinstance(expectedError.description, (bytes, str)):
            self.assertEqual(
                expectedError.description.encode('utf-8'), errorResult['error_description'],
                msg=msg + ': Result contained a different error description than expected.')
        else:
            self.assertEqual(
                expectedError.description, errorResult['error_description'],
                msg=msg + ': Result contained a different error description than expected.')
        if expectedError.errorUri is not None:
            self.assertIn('error_uri', errorResult,
                          msg=msg + ': Missing error_uri parameter in response.')
            self.assertEqual(expectedError.errorUri, errorResult['error_uri'],
                             msg=msg + ': Result contained an unexpected error_uri.')
        if hasattr(expectedError, 'state') and getattr(expectedError, 'state') is not None:
            self.assertIn('state', errorResult, msg=msg + ': Missing state parameter in response.')
            self.assertEqual(
                expectedError.state if isinstance(expectedError.state, str)
                else expectedError.state.decode('utf-8', errors='replace'), errorResult['state'],
                msg=msg + ': Result contained an unexpected state.')

    def assertValidAuthRequest(self, request, result, parameters, msg, expectedDataLifetime=None):
        """
        Assert that a GET request is processed correctly and the expected data has been stored.

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
        self.assertEqual(parameters['client_id'], client.id,
                         msg=msg + ': Expected the auth resource to pass the received '
                                   'client to onAuthenticate as the second parameter.')
        parameters['response_type'] = self._RESPONSE_GRANT_TYPE_MAPPING.get(
            parameters['response_type'], parameters['response_type'])
        self.assertEqual(parameters['response_type'], responseType,
                         msg=msg + ': Expected the auth resource to pass the response '
                                   'type to onAuthenticate as the third parameter.')
        parameters['scope'] = parameters['scope'].split(' ')
        self.assertListEqual(scope, parameters['scope'],
                             msg=msg + ': Expected the auth resource to pass the scope '
                                       'to onAuthenticate as the fourth parameter.')
        expectedRedirectUri = parameters['redirect_uri'] if parameters['redirect_uri'] is not None \
            else self._VALID_CLIENT.redirectUris[0]
        self.assertEqual(expectedRedirectUri, redirectUri,
                         msg=msg + ': Expected the auth resource to pass the redirect '
                                   'uri to onAuthenticate as the fifth parameter.')
        expectedState = parameters.get('state', None)
        self.assertEqual(expectedState, state,
                         msg=msg + ': Expected the auth resource to pass the state '
                                   'to onAuthenticate as the sixth parameter.')
        if expectedDataLifetime is None:
            expectedDataLifetime = self._AUTH_RESOURCE.requestDataLifetime
        try:
            self.assertEqual(expectedDataLifetime, self._PERSISTENT_STORAGE.getExpireTime(dataKey),
                             msg=msg + ': Expected the auth resource to store '
                                       'the request data with the given lifetime.')
            data = self._PERSISTENT_STORAGE.pop(dataKey)
        except KeyError:
            self.fail(msg=msg + ': Expected the auth resource to pass a valid '
                                'data key to onAuthenticate as the sixth parameter.')
        for key, value in parameters.items():
            self.assertIn(key, data, msg=msg + ': Expected the data stored by auth token resource '
                                               'to contain the {name} parameter.'.format(name=key))
            self.assertEqual(value, data[key],
                             msg=msg + ': Expected the auth token resource to store the value '
                                       'of the {name} parameter.'.format(name=key))


class AuthResourceTest(AbstractAuthResourceTest):
    """ Tests aspects of the OAuth2 resource that do not depend on the response type. """

    def testWithoutResponseType(self):
        """ Test the rejection of a request without a response type. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
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
        request = self.createAuthRequest(arguments={
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
        request = self.createAuthRequest(arguments={
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
        request = self.createAuthRequest(arguments={
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
        request = self.createAuthRequest(arguments=parameters, isSecure=False)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InsecureConnectionError(), redirectUri=redirectUri,
            msg='Expected the auth resource to reject a request over an insecure transport.')
        authResource = self.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            allowInsecureRequestDebug=True, authTokenStorage=self._TOKEN_STORAGE)
        request = self.createAuthRequest(arguments=parameters, isSecure=False)
        result = authResource.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameters,
            msg='Expected the auth resource to accept a request over an '
                'insecure transport if allowInsecureRequestDebug is true.')

    def testErrorInOnAuthenticate(self):
        """ Test that an error in onAuthenticate is caught and a ServerError is returned. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        self._AUTH_RESOURCE.raiseErrorInOnAuthenticate = True
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, ServerError(state=state, message=self._AUTH_RESOURCE.ERROR_MESSAGE),
            redirectUri=redirectUri,
            msg='Expected the auth resource to catch errors thrown in the onAuthenticate method.')

    def testSendsErrorInOnAuthenticate(self):
        """ Test that any AuthorizationErrors raised in onAuthenticate are handled. """
        state = b'state\xFF\xFF'
        scope = self._AUTH_RESOURCE.UNKNOWN_SCOPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': scope,
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InvalidScopeError(scope, state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to send the error raised by the onAuthenticate method.')

    def testSendsErrorReturnedByOnAuthenticate(self):
        """
        Test that any AuthorizationErrors returned by onAuthenticate
        are handled with a deprecation warning.
        """
        state = b'state\xFF\xFF'
        scope = self._AUTH_RESOURCE.UNKNOWN_SCOPE_RETURN
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': scope,
            'state': state
        })
        with warnings.catch_warnings(record=True) as caughtWarnings:
            warnings.simplefilter('always')
            result = self._AUTH_RESOURCE.render_GET(request)
            self.assertEqual(
                1, len(caughtWarnings),
                msg='Expected the OAuth2 resource to generate a warning, if '
                    'onAuthenticate returns an OAuth2Error instead of raising it')
            self.assertTrue(issubclass(caughtWarnings[0].category, DeprecationWarning),
                            msg='Expected the token resource to generate a DeprecationWarning')
            self.assertIn(
                'Returning an error from onAuthenticate is deprecated',
                str(caughtWarnings[0].message),
                msg='Expected the token resource to generate a DeprecationWarning explaining that '
                    'returning an error from onAuthenticate is deprecated.')
        self.assertFailedRequest(
            request, result, InvalidScopeError(scope, state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to send the error '
                'returned from the onAuthenticate method.')

    def testWarnsIfOnAuthenticateThrowsAnOAuth2Error(self):
        """ Test that any OAuth2Error returned by onAuthenticate produces a warning. """
        state = b'state\xFF\xFF'
        scope = self._AUTH_RESOURCE.UNKNOWN_SCOPE_RAISING_OAUTH2_ERROR
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': scope,
            'state': state
        })
        with warnings.catch_warnings(record=True) as caughtWarnings:
            warnings.simplefilter('always')
            result = self._AUTH_RESOURCE.render_GET(request)
            self.assertEqual(
                1, len(caughtWarnings),
                msg='Expected the OAuth2 resource to generate a warning, if '
                    'onAuthenticate returns an OAuth2Error instead of raising it')
            self.assertTrue(issubclass(caughtWarnings[0].category, RuntimeWarning),
                            msg='Expected the token resource to generate a RuntimeWarning')
            self.assertIn(
                'Only AuthorizationErrors are expected to occur during authorization',
                str(caughtWarnings[0].message),
                msg='Expected the token resource to generate a warning explaining that '
                    'only AuthorizationErrors are expected to occur during authorization.')
        self.assertFailedRequest(
            request, result, ServerError(
                state=state, message='invalid_grant: The provided {type} is invalid'.format(
                    type=self._AUTH_RESOURCE.ERROR_MESSAGE)), redirectUri=redirectUri,
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
        request = self.createAuthRequest(arguments=parameters)
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
        request = self.createAuthRequest(arguments=parameters)
        self._CLIENT_STORAGE.addClient(client)
        authResource = self.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            authTokenStorage=self._TOKEN_STORAGE, grantTypes=[responseType])
        result = authResource.render_GET(request)
        self.assertFailedRequest(
            request, result, UnauthorizedClientError(responseType, state), redirectUri=redirectUri,
            msg='Expected the authorization token resource to reject a request with a '
                'custom response type that the client is not allowed to use.')

    def testInsecureRedirectUriClient(self):
        """ Test that a request with a non https redirect uri is accepted. """
        state = b'state\xFF\xFF'
        client = PasswordClient('customResponseTypeClientUnauthorized', ['custom://callback'],
                                [GrantTypes.AuthorizationCode], 'clientSecret')
        redirectUri = client.redirectUris[0]
        parameters = {
            'response_type': 'code',
            'client_id': client.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        }
        request = self.createAuthRequest(arguments=parameters)
        self._CLIENT_STORAGE.addClient(client)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameters, msg='Expected the authorization token resource to accept '
                                             'a valid request with a non https redirect uri.')

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
        request = self.createAuthRequest(arguments=parameters)
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
            self.assertEqual(self._AUTH_RESOURCE.requestDataLifetime,
                             self._PERSISTENT_STORAGE.getExpireTime(dataKey),
                             msg='Expected the data to be stored with the expected lifetime.')
            self._PERSISTENT_STORAGE.pop(dataKey)
        except KeyError:
            self.fail('Expected the data to still be in the persistent storage.')

    def testWithMultipleStates(self):
        """ Test the rejection of a request with multiple states. """
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': [b'state\xFF\xFF'] * 2
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MultipleParameterError('state'),
            redirectUri=redirectUri, msg='Expected the auth resource to reject '
                                         'a request with multiple states.')

    def testRequiresTokenLifetime(self):
        """ Test that the authorization resource requires a token lifetime. """
        self.assertRaises(ValueError, self.TestOAuth2Resource, self._TOKEN_FACTORY,
                          self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
                          authTokenStorage=self._TOKEN_STORAGE, authTokenLifeTime=None)

    def testRequiresTokenStorageOnImplicitGrant(self):
        """
        Test that the authorization resource requires a token storage
        if the implicit grant flow is enabled.
        """
        self.assertRaises(ValueError, self.TestOAuth2Resource, self._TOKEN_FACTORY,
                          self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
                          grantTypes=[GrantTypes.Implicit])

    def testTemporaryUnavailable(self):
        """ Test that the OAuth2 resource correctly handles a TemporarilyUnavailableError. """
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        state = b'state\xFF\xFF'
        request = self.createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': self.TestOAuth2Resource.TEMPORARY_UNAVAILABLE_SCOPE,
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, TemporarilyUnavailableError(state=state),
            redirectUri=redirectUri, msg='Expected the auth resource to correctly report a '
                                         'TemporarilyUnavailableError error.')
