from oauth2 import isAuthorized
from oauth2.errors import MissingTokenError, InvalidTokenRequestError
from tests import MockRequest, TwistedTestCase


class TestIsAuthorized(TwistedTestCase):
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
        pass

    def testWithAccessTokenInBody(self):
        # See https://tools.ietf.org/html/rfc6750#section-2.2
        pass

    def testWithAccessTokenInQuery(self):
        # See https://tools.ietf.org/html/rfc6750#section-2.3
        pass

    def testMultipleAccessTokens(self):
        pass

    def testRequestOverInsecureTransport(self):
        pass
