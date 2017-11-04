from oauth2 import isAuthorized
from oauth2.token import TokenResource
from oauth2.errors import MissingTokenError, InvalidTokenRequestError,\
    InsufficientScopeRequestError
from tests import MockRequest, TwistedTestCase, MockTokenStorage


class TestIsAuthorized(TwistedTestCase):
    VALID_TOKEN = 'valid_token'
    VALID_TOKEN_SCOPE = ['All', 'scope1']

    def setUp(self):
        tokenStorage = MockTokenStorage()
        setattr(TokenResource, '_OAuthTokenStorage', tokenStorage)
        tokenStorage.store(self.VALID_TOKEN, None, self.VALID_TOKEN_SCOPE)

    def tearDown(self):
        setattr(TokenResource, '_OAuthTokenStorage', None)

    def assertFailedProtectedResourceRequest(self, request, expectedError):
        self.assertEqual(
            expectedError.code, request.responseCode,
            msg='The HTTP response code should be {code}, if a protected resource receives a '
                'request without or with an invalid token.'.format(code=expectedError.code))
        header = request.getResponseHeader('WWW-Authenticate')
        self.assertIsNotNone(header, msg='Responses to requests without or with invalid tokens '
                                         'must contain a "WWW-Authenticate" header.')
        self.assertTrue(header.startswith('Bearer'),msg='The "WWW-Authenticate" header must start '
                                                        'with the auth-scheme value "Bearer".')
        self.assertTrue(header.strip() != 'Bearer' and '=' in header,
                        msg='The "WWW-Authenticate" header must '
                            'have one or more auth-param values.')
        authParameter = {
            'realm': request.prePathURL(),
            'scope': ' '.join(expectedError.scope),
            'error': expectedError.message,
            'error_description': expectedError.detail
        }
        if expectedError.errorUri is not None:
            authParameter['error_uri'] = expectedError.errorUri
        if isinstance(expectedError, MissingTokenError):
            authParameter = {'realm': authParameter['realm']}
        for key, content in authParameter.items():
            self.assertTrue(key + '=' not in header.replace(key + '=', ''),
                            msg='The "{key}" auth-parameter must not be present multiple times.'
                            .format(key=key))
            self.assertIn('{key}="{value}"'.format(key=key, value=content), header,
                          msg='The "{key}" auth-parameter does not contain the expected value.'
                          .format(key=key))
        self.assertTrue(request.finished, msg='Expected the request to be closed '
                                              'after it has been rejected.')

    def testNoAccessToken(self):
        request = MockRequest('GET', 'protectedResource')
        self.assertFalse(isAuthorized(request, 'scope'),
                         msg='Expected isAuthorized to reject a request without a token.')
        self.assertFailedProtectedResourceRequest(request, MissingTokenError(['scope']))

    def testWrongAccessToken(self):
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', b'an invalid token')
        self.assertFalse(isAuthorized(request, 'scope'),
                         msg='Expected isAuthorized to reject a request with an invalid token.')
        self.assertFailedProtectedResourceRequest(request, InvalidTokenRequestError(['scope']))

    def testMalformedAccessToken(self):
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', b'Bearer malformed token \xFF\xFF\xFF\xFF')
        self.assertFalse(isAuthorized(request, 'scope'),
                         msg='Expected isAuthorized to reject a request with a malformed token.')
        self.assertFailedProtectedResourceRequest(request, InvalidTokenRequestError(['scope']))

    def testWithAccessTokenInHeader(self):
        # See https://tools.ietf.org/html/rfc6750#section-2.1
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', 'Bearer ' + self.VALID_TOKEN)
        self.assertTrue(isAuthorized(request, self.VALID_TOKEN_SCOPE[0]),
                        msg='Expected isAuthorized to accept a request with a valid token.')
        self.assertFalse(request.finished,
                         msg='isAuthorized should not finish the request if its valid.')

    def testWithAccessTokenInBody(self):
        # See https://tools.ietf.org/html/rfc6750#section-2.2
        pass

    def testWithAccessTokenInQuery(self):
        # See https://tools.ietf.org/html/rfc6750#section-2.3
        pass

    def testMultipleAccessTokens(self):
        pass

    def testInvalidScope(self):
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', 'Bearer ' + self.VALID_TOKEN)
        self.assertFalse(isAuthorized(request, 'someOtherScope'),
                         msg='Expected isAuthorized to reject a request with token '
                             'that does not allow access to the given scope.')
        self.assertFailedProtectedResourceRequest(
            request, InsufficientScopeRequestError(['someOtherScope']))

    def testRequestOverInsecureTransport(self):
        request = MockRequest('GET', 'protectedResource', isSecure=False)
        request.setRequestHeader(b'Authorization', 'Bearer ' + self.VALID_TOKEN)
        self.assertTrue(isAuthorized(request, self.VALID_TOKEN_SCOPE,
                                     allowInsecureRequestDebug=True),
                        msg='Expected isAuthorized to accept a request over an insecure protocol '
                            'if "allowInsecureRequestDebug" is set to True.')
        self.assertFalse(isAuthorized(request, self.VALID_TOKEN_SCOPE),
                         msg='Expected isAuthorized to reject a request over an insecure protocol.')
        self.assertEqual(
            400, request.responseCode,
            msg='The HTTP response code should be {code}, if a protected resource receives a '
                'request over an insecure channel.'.format(code=400))
