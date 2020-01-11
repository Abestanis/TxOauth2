""" Tests that addition of custom grant flows. """

from txoauth2.errors import UnsupportedGrantTypeError
from txoauth2.token import TokenResource

from tests.unit.testTokenResource import AbstractTokenResourceTest


class TestExtensionGrant(AbstractTokenResourceTest):
    """
    Test that one can use a custom authorization method to authorize a token request.
    See https://tools.ietf.org/html/rfc6749#section-4.5
    """

    class TestTokenResource(TokenResource):
        """ A test TokenResource that returns the parameter given to onCustomGrantTypeRequest. """

        def onCustomGrantTypeRequest(self, request, grantType):
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

    def testCustomGrantTypeNotAllowed(self):
        """ Test that a request with a custom grant type is rejected if it is not enabled. """
        grantType = 'myCustomGrantType'
        request = self.generateValidTokenRequest(arguments={'grant_type': grantType})
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, UnsupportedGrantTypeError(grantType),
            msg='Expected the token resource to reject a request with '
                'a custom grant type that is not allowed.')
