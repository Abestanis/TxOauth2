import os
import sys
import importlib

from tests import MockSite, MockRequest, TwistedTestCase


class FullExampleTestCase(TwistedTestCase):
    """
    Test case that tests that the OAuth2 specification is respected by applying
    the routines specified by the specification to the example server.
    """
    server = None

    def setUp(self):
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'example')))
        exampleModule = importlib.import_module('main')
        self.server = MockSite(exampleModule.setupTestServerResource())

    def assertFailedProtectedResourceRequest(self, request, scope, error, errorDescription):
        self.assertEqual(401, request.responseCode,
                         msg='The HTTP response code should be 401, if a protected '
                             'resource receives a request without or with an invalid token.')
        header = request.getHeader('WWW-Authenticate')
        self.assertIsNotNone(header, msg='Responses to requests without or with invalid tokens '
                                         'must contain a "WWW-Authenticate" header.')
        self.assertTrue(header.startsWith('Bearer'), msg='The "WWW-Authenticate" header must start '
                                                         'with the auth-scheme value "Bearer".')
        self.assertTrue(header.strip() != 'Bearer' and '=' in header,
                        msg='The "WWW-Authenticate" header must '
                            'have one or more auth-param values.')
        authParameter = {
            'realm': request.prePathURL(),
            'scope': ' '.join(scope),
            'error': error,
            'error_description': errorDescription
        }
        for key, content in authParameter.items():
            self.assertTrue(key + '=' not in header.replace(key + '=', ''),
                            msg='The "{key}" auth-parameter must not be present multiple times.'
                            .format(key=key))
            self.assertIn('{key}="{value}"'.format(key=key, value=content), header,
                          msg='The "{key}" auth-parameter does not contain the expected value.'
                          .format(key=key))

    def testAccessClockResourceWithoutToken(self):
        request = MockRequest('GET', 'clock')
        self.server.makeSynchronousRequest(request)
        self.assertEqual(401, request.responseCode, msg='Expected the protected clock resource '
                                                        'to reject a request without a token.')
        self.assertNotSubstring(b'<html><body>', request.getResponse(),
                                msg='Expected the protected clock resource '
                                    'not to send the protected content.')

    def testAccessClockResourceWithValidToken(self):
        pass
