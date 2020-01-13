""" Tests that addition of custom grant flows. """
import warnings

from txoauth2.errors import UnsupportedGrantTypeError, ServerError, InvalidParameterError
from txoauth2.token import TokenResource

from tests.unit.testTokenResource import AbstractTokenResourceTest


class TestExtensionGrant(AbstractTokenResourceTest):
    """
    Test that one can use a custom authorization method to authorize a token request.
    See https://tools.ietf.org/html/rfc6749#section-4.5
    """

    class TestTokenResource(TokenResource):
        """ A test TokenResource that returns the parameter given to onCustomGrantTypeRequest. """

        def __init__(self, *args, error=None, returnError=False, **kwargs):
            super().__init__(*args, **kwargs)
            self.error = error
            self.returnError = returnError

        def onCustomGrantTypeRequest(self, request, grantType):
            if self.error is not None:
                if self.returnError:
                    return self.error
                raise self.error
            return request, grantType

    def testCustomGrantType(self):
        """ Test that a request with a custom grant type is accepted. """
        grantType = 'myCustomGrantType'
        request = self.generateValidTokenRequest(arguments={'grant_type': grantType})
        tokenResource = self.TestTokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, grantTypes=[grantType])
        result = tokenResource.render_POST(request)
        self.assertIsInstance(
            result, tuple, message='Expected the token resource to call '
                                   'onCustomGrantTypeRequest for a custom grant type.')
        self.assertFalse(request.finished,
                         msg='Expected the token resource not to close the request.')
        self.assertIs(result[0], request, msg='Expected the token resource to pass '
                                              'the request to onCustomGrantTypeRequest.')
        self.assertEqual(result[1], grantType, msg='Expected the token resource to pass the '
                                                   'grant type to onCustomGrantTypeRequest.')

    def testCustomGrantTypeError(self):
        """ Test that errors can be returned from the onCustomGrantTypeRequest function. """
        grantType = 'myCustomGrantType'
        request = self.generateValidTokenRequest(arguments={'grant_type': grantType})
        errorMessage = 'Test error message'
        tokenResource = self.TestTokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, grantTypes=[grantType],
            error=ValueError(errorMessage))
        result = tokenResource.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, ServerError(message=errorMessage),
            'Expected the token resource to wrap any Python errors from '
            'onCustomGrantTypeRequest into a server error')
        tokenResource = self.TestTokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, grantTypes=[grantType],
            error=InvalidParameterError('testName'))
        result = tokenResource.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidParameterError('testName'),
            'Expected the token resource catch any OAuth2Error')
        tokenResource = self.TestTokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, grantTypes=[grantType],
            error=InvalidParameterError('testName'), returnError=True)
        with warnings.catch_warnings(record=True) as caughtWarnings:
            warnings.simplefilter('always')
            result = tokenResource.render_POST(request)
            self.assertEqual(
                len(caughtWarnings), 1,
                msg='Expected the token resource to generate a warning, if '
                    'onCustomGrantTypeRequest returns an OAuth2Error instead of raising it')
            self.assertTrue(issubclass(caughtWarnings[0].category, DeprecationWarning),
                            msg='Expected the token resource to generate a DeprecationWarning')
            self.assertIn(
                'Returning an error from onCustomGrantTypeRequest is deprecated',
                str(caughtWarnings[0].message),
                msg='Expected the token resource to generate a DeprecationWarning explaining that '
                    'returning an error from onCustomGrantTypeRequest is deprecated.')
        self.assertFailedTokenRequest(
            request, result, InvalidParameterError('testName'),
            'Expected the token resource detect a returned OAuth2Error '
            'and return a valid error response')

    def testCustomGrantTypeNotAllowed(self):
        """ Test that a request with a custom grant type is rejected if it is not enabled. """
        grantType = 'myCustomGrantType'
        request = self.generateValidTokenRequest(arguments={'grant_type': grantType})
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, UnsupportedGrantTypeError(grantType),
            msg='Expected the token resource to reject a request with '
                'a custom grant type that is not allowed.')
