from itertools import combinations

from txoauth2 import GrantTypes
from txoauth2.token import TokenResource
from txoauth2.errors import MissingParameterError, MultipleParameterError, InvalidTokenError, \
    InvalidScopeError, UnauthorizedClientError

from tests import getTestPasswordClient, ensureByteString
from tests.unit.testTokenResource import AbstractTokenResourceTest


class TestTokenRefresh(AbstractTokenResourceTest):
    """
    Test the refreshing of an access and refresh token.
    See https://tools.ietf.org/html/rfc6749#section-6
    """

    def testNoRefreshToken(self):
        """ Test the rejection of a request without a refresh token. """
        request = self._generateValidTokenRequest(arguments={'grant_type': 'refresh_token'},
                                                  authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, MissingParameterError('refresh_token'),
                                      msg='Expected the token resource to reject a refresh_token '
                                          'request without a refresh token.')

    def testMultipleRefreshToken(self):
        """ Test the rejection of a request with multiple refresh tokens. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': [self._VALID_REFRESH_TOKEN, self._VALID_REFRESH_TOKEN]
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, MultipleParameterError('refresh_token'),
                                      msg='Expected the token resource to reject a refresh_token '
                                          'request with multiple refresh tokens.')

    def testInvalidRefreshToken(self):
        """ Test the rejection of a request with an invalid refresh token. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': 'invalidRefreshToken'
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, InvalidTokenError('refresh token'),
                                      msg='Expected the token resource to reject a refresh_token '
                                          'request with multiple refresh tokens.')

    def testMalformedRefreshToken(self):
        """ Test the rejection of a request with a malformed refresh token. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': b'malformedRefreshToken\xFF\xFF'
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, InvalidTokenError('refresh token'),
                                      msg='Expected the token resource to reject a refresh_token '
                                          'request with a malformed refresh tokens.')

    def testNoScope(self):
        """ Test the acceptance of a valid request with no scope. """
        newAuthToken = 'newAuthTokenWithoutScope'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': self._VALID_REFRESH_TOKEN
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(newAuthToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                                               self._VALID_CLIENT, self._VALID_SCOPE)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(
            request, result, newAuthToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedScope=self._VALID_SCOPE)

    def testWithScope(self):
        """ Test the acceptance of a valid request with a valid scope. """
        newAuthToken = 'newAuthTokenWithScope'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': self._VALID_REFRESH_TOKEN,
            'scope': ' '.join(self._VALID_SCOPE)
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(newAuthToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                                               self._VALID_CLIENT, self._VALID_SCOPE)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(
            request, result, newAuthToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedScope=self._VALID_SCOPE)

    def testInvalidScope(self):
        """ Test the rejection of a valid request with an invalid scope. """
        invalidScope = 'invalidScope'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': self._VALID_REFRESH_TOKEN,
            'scope': invalidScope
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, InvalidScopeError(invalidScope),
                                      msg='Expected the token resource to reject a refresh_token '
                                          'request with an invalid scope.')

    def testMalformedScope(self):
        """ Test the rejection of a valid request with a malformed scope. """
        malformedScope = b'malformedScope\xFF\xFF'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': self._VALID_REFRESH_TOKEN,
            'scope': malformedScope
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidScopeError(ensureByteString(malformedScope)),
            msg='Expected the token resource to reject a '
                'refresh_token request with an malformed scope.')

    def testSubsetScope(self):
        """ Test the acceptance of a valid request with a valid sub-scope. """
        for scopeSubset in combinations(self._VALID_SCOPE, len(self._VALID_SCOPE) - 1):
            newAuthToken = 'newAuthTokenWithSunsetScope' + str(id(scopeSubset))
            scopeSubset = list(scopeSubset)
            request = self._generateValidTokenRequest(arguments={
                'grant_type': 'refresh_token',
                'refresh_token': self._VALID_REFRESH_TOKEN,
                'scope': scopeSubset
            }, authentication=self._VALID_CLIENT)
            self._TOKEN_FACTORY.expectTokenRequest(
                newAuthToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                self._VALID_CLIENT, scopeSubset)
            result = self._TOKEN_RESOURCE.render_POST(request)
            self._TOKEN_FACTORY.assertAllTokensRequested()
            self.assertValidTokenResponse(
                request, result, newAuthToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                expectedScope=scopeSubset)

    def testWrongClient(self):
        """ Test the rejection of a request with a valid refresh token for a different client. """
        client = getTestPasswordClient(
            clientId='differentClient', authorizedGrantTypes=[GrantTypes.RefreshToken])
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': self._VALID_REFRESH_TOKEN,
        }, authentication=client)
        self._CLIENT_STORAGE.addClient(client)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidTokenError('refresh token'),
            msg='Expected the token resource to reject a refresh_token request '
                'with a refresh token that is not valid for the client.')

    def testUnauthorizedGrantTypeClient(self):
        """ Test the rejection of a valid request for an unauthorized client. """
        client = getTestPasswordClient(clientId='unauthorizedClient', authorizedGrantTypes=[])
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'client_id': client.id,
            'client_secret': client.secret,
            'refresh_token': self._VALID_REFRESH_TOKEN,
        })
        self._CLIENT_STORAGE.addClient(client)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, UnauthorizedClientError('refresh_token'),
            msg='Expected the token resource to reject a refresh_token request '
                'for the client that is not authorized to use that grant type.')

    def testAuthTokenLifetime(self):
        """ Test that the token lifetime of the new auth token equals the specified value. """
        tokenLifetime = 60
        newAuthToken = 'newAuthTokenWithoutChangedLifetime'
        tokenResource = TokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, authTokenLifeTime=tokenLifetime,
            passwordManager=self._PASSWORD_MANAGER)
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': self._VALID_REFRESH_TOKEN
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(
            newAuthToken, tokenLifetime, self._VALID_CLIENT, self._VALID_SCOPE)
        result = tokenResource.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(request, result, newAuthToken, tokenLifetime,
                                      expectedScope=self._VALID_SCOPE)

    def testInfiniteTokenLifetime(self):
        """ Test that the token lifetime of the new auth token can be infinite. """
        tokenLifetime = None
        newAuthToken = 'newAuthTokenWithoutChangedLifetime'
        tokenResource = TokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, authTokenLifeTime=tokenLifetime,
            passwordManager=self._PASSWORD_MANAGER)
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': self._VALID_REFRESH_TOKEN
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(
            newAuthToken, tokenLifetime, self._VALID_CLIENT, self._VALID_SCOPE)
        result = tokenResource.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(request, result, newAuthToken, tokenLifetime,
                                      expectedScope=self._VALID_SCOPE)

    def testRefreshTokenRenewal(self):
        """ Test that the refresh token is refreshed when expected. """
        self.fail('Implement')
