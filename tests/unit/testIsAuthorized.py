from txoauth2 import isAuthorized, oauth2
from txoauth2.imp import DictTokenStorage
from txoauth2.token import TokenResource
from txoauth2.errors import MissingTokenError, InvalidTokenRequestError, \
    InsufficientScopeRequestError, MultipleTokensError

from tests import MockRequest, TwistedTestCase, getTestPasswordClient


class TestIsAuthorized(TwistedTestCase):
    VALID_TOKEN = 'valid_token'
    VALID_TOKEN_SCOPE = ['All', 'scope1']

    @classmethod
    def setUpClass(cls):
        tokenStorage = DictTokenStorage()
        setattr(TokenResource, '_OAuthTokenStorage', tokenStorage)
        tokenStorage.store(cls.VALID_TOKEN, getTestPasswordClient(), cls.VALID_TOKEN_SCOPE)

    @classmethod
    def tearDownClass(cls):
        setattr(TokenResource, '_OAuthTokenStorage', None)

    def assertFailedProtectedResourceRequest(self, request, expectedError):
        """
        Assert that request has been closed and
        that the expected error has been send as a response.
        :param request: The request to check.
        :param expectedError: The error that should have been written as the response.
        """
        self.assertEqual(
            expectedError.code, request.responseCode,
            msg='The HTTP response code should be {code}, if a protected resource receives a '
                'request without or with an invalid token.'.format(code=expectedError.code))
        header = request.getResponseHeader('WWW-Authenticate')
        self.assertIsNotNone(header, msg='Responses to requests without or with invalid tokens '
                                         'must contain a "WWW-Authenticate" header.')
        self.assertTrue(header.startswith('Bearer'), msg='The "WWW-Authenticate" header must start '
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
        """ Test the rejection of a request to a protected resource without a token. """
        request = MockRequest('GET', 'protectedResource')
        self.assertFalse(isAuthorized(request, 'scope'),
                         msg='Expected isAuthorized to reject a request without a token.')
        self.assertFailedProtectedResourceRequest(request, MissingTokenError(['scope']))

    def testWrongAccessToken(self):
        """ Test the rejection of a request to a protected resource with an invalid token. """
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', b'Bearer an invalid token')
        self.assertFalse(isAuthorized(request, 'scope'),
                         msg='Expected isAuthorized to reject a request with an invalid token.')
        self.assertFailedProtectedResourceRequest(request, InvalidTokenRequestError(['scope']))

    def testMalformedAccessToken(self):
        """ Test the rejection of a request to a protected resource with a malformed token. """
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', b'Bearer malformed token \xFF\xFF\xFF\xFF')
        self.assertFalse(isAuthorized(request, 'scope'),
                         msg='Expected isAuthorized to reject a request with a malformed token.')
        self.assertFailedProtectedResourceRequest(request, InvalidTokenRequestError(['scope']))

    def testWithAccessTokenInHeader(self):
        """
        Test a request to a protected resource with a valid token in the Authorization header.
        See https://tools.ietf.org/html/rfc6750#section-2.1
        """
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', 'Bearer ' + self.VALID_TOKEN)
        self.assertTrue(isAuthorized(request, self.VALID_TOKEN_SCOPE[0]),
                        msg='Expected isAuthorized to accept a request with a valid token.')
        self.assertFalse(request.finished,
                         msg='isAuthorized should not finish the request if it\'s valid.')

    def testWithAccessTokenInBody(self):
        """
        Test a request to a protected resource with a valid token in the request body.
        See https://tools.ietf.org/html/rfc6750#section-2.2
        """
        request = MockRequest(
            'POST', 'protectedResource', arguments={'access_token': self.VALID_TOKEN})
        request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded')
        self.assertTrue(isAuthorized(request, self.VALID_TOKEN_SCOPE[0]),
                        msg='Expected isAuthorized to accept a request '
                            'with a valid token in the request body.')
        self.assertFalse(request.finished,
                         msg='isAuthorized should not finish the request if it\'s valid.')

    def testWithAccessTokenInQuery(self):
        """
        Test a request to a protected resource with a valid token in the request query.
        See https://tools.ietf.org/html/rfc6750#section-2.3
        """
        request = MockRequest('GET', 'protectedResource?access_token=' + self.VALID_TOKEN)
        self.assertTrue(isAuthorized(request, self.VALID_TOKEN_SCOPE[0]),
                        msg='Expected isAuthorized to accept a request '
                            'with a valid token as a query parameter.')
        self.assertFalse(request.finished,
                         msg='isAuthorized should not finish the request if it\'s valid.')
        self.assertIn('private', request.getResponseHeader('Cache-Control'),
                      msg='The response to a request with the access token as a query parameter '
                          'should contain a Cache-Control header with the "private" option.')

    def testAccessTokenInBodyWrongMethod(self):
        """
        Test the rejection of a request to a protected resource with a valid token
        in the request body but a request that was not made with the POST method.
        """
        request = MockRequest(
            'GET', 'protectedResource', arguments={'access_token': self.VALID_TOKEN})
        request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded')
        self.assertFalse(isAuthorized(request, self.VALID_TOKEN_SCOPE),
                         msg='Expected isAuthorized to reject a request with a valid token '
                             'in the request body that was not send with the POST method.')
        self.assertFailedProtectedResourceRequest(
            request, MissingTokenError(self.VALID_TOKEN_SCOPE))

    def testAccessTokenInBodyWrongContentType(self):
        """
        Test the rejection of a request to a protected resource
        with a valid token but an invalid content type.
        """
        request = MockRequest(
            'POST', 'protectedResource', arguments={'access_token': self.VALID_TOKEN})
        request.setRequestHeader('Content-Type', 'application/other')
        self.assertFalse(isAuthorized(request, self.VALID_TOKEN_SCOPE),
                         msg='Expected isAuthorized to reject a request '
                             'with a valid token in the request body with a content type '
                             'that is not "application/x-www-form-urlencoded".')
        self.assertFailedProtectedResourceRequest(
            request, MissingTokenError(self.VALID_TOKEN_SCOPE))

    def testMultipleAccessTokens(self):
        """ Test the rejection of a request to a protected resource with multiple tokens. """
        request = MockRequest('GET', 'protectedResource?access_token=' + self.VALID_TOKEN
                              + '&access_token=' + self.VALID_TOKEN)
        self.assertFalse(isAuthorized(request, self.VALID_TOKEN_SCOPE),
                         msg='Expected isAuthorized to reject a request with two tokens.')
        self.assertFailedProtectedResourceRequest(
            request, MultipleTokensError(self.VALID_TOKEN_SCOPE))
        request = MockRequest('GET', 'protectedResource?access_token=' + self.VALID_TOKEN)
        request.setRequestHeader(b'Authorization', 'Bearer ' + self.VALID_TOKEN)
        self.assertFalse(isAuthorized(request, self.VALID_TOKEN_SCOPE),
                         msg='Expected isAuthorized to reject a request with two tokens.')
        self.assertFailedProtectedResourceRequest(
            request, MultipleTokensError(self.VALID_TOKEN_SCOPE))

    def testInvalidScope(self):
        """
        Test the rejection of a request to a protected resource
        with a valid token that does not grant access to the necessary scopes.
        """
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', 'Bearer ' + self.VALID_TOKEN)
        self.assertFalse(isAuthorized(request, 'someOtherScope'),
                         msg='Expected isAuthorized to reject a request with token '
                             'that does not allow access to the given scope.')
        self.assertFailedProtectedResourceRequest(
            request, InsufficientScopeRequestError(['someOtherScope']))

    def testRequestOverInsecureTransport(self):
        """
        Test the rejection of a request to a protected resource
        with a valid token that was made over an insecure protocol.
        """
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

    def testDecorator(self):
        """ Test that the oauth2 functions as expected. """
        protectedContent = b'protectedContent'

        @oauth2(self.VALID_TOKEN_SCOPE)
        def render(selfArg, requestArg):
            del selfArg, requestArg  # Unused
            return protectedContent
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', 'Bearer ' + self.VALID_TOKEN)
        self.assertEquals(protectedContent, render(self, request),
                          msg='Expected oauth2 to accept a valid request.')
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', 'Bearer invalidToken')
        self.assertNotEqual(protectedContent, render(self, request),
                            msg='Expected oauth2 to reject a request with an invalid token.')
        request = MockRequest('GET', 'protectedResource')
        request.setRequestHeader(b'Authorization', 'Bearer ' + self.VALID_TOKEN)

        @oauth2(['Other'])
        def render2(selfArg, requestArg):
            del selfArg, requestArg  # Unused
            return protectedContent
        self.assertNotEqual(protectedContent, render2(self, request),
                            msg='Expected oauth2 to reject a request with an invalid scope.')
