from txoauth2.clients import PublicClient
from txoauth2.token import TokenResource
from txoauth2.errors import UnauthorizedClientError, MissingParameterError, \
    MultipleParameterError, InvalidScopeError

from tests import getTestPasswordClient
from tests.unit.testTokenResource import AbstractTokenResourceTest


class TestClientCredentialsGrant(AbstractTokenResourceTest):
    """
    Test the functionality of the Client Credentials Grant.
    See https://tools.ietf.org/html/rfc6749#section-4.4
    """
    def testUnauthorizedClient(self):
        """
        Test the rejection of a request with a client who is
        not authorized to use the Client Credentials grant.
        """
        client = getTestPasswordClient('unauthorizedClientCredentialsGrantClient',
                                       authorizedGrantTypes=[])
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'client_credentials',
            'scope': ' '.join(self._VALID_SCOPE),
        }, authentication=client)
        self._CLIENT_STORAGE.addClient(client)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, UnauthorizedClientError('client_credentials'),
            msg='Expected the resource token to reject a client_credentials request '
                'with a client that is not authorized to use that grant type.')

    def testPublicClient(self):
        """ Test the rejection of a request with a public client. """
        client = PublicClient('unauthorizedClientCredentialsGrantClient',
                              ['https://return.nonexistent'], ['client_credentials'])
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'client_credentials',
            'scope': ' '.join(self._VALID_SCOPE),
            'client_id': client.id
        })
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, UnauthorizedClientError('client_credentials'),
            msg='Expected the resource token to reject a '
                'client_credentials request with a public client.')

    def testAuthorizedClientWithoutScope(self):
        """
        Test that of a request without a scope is accepted
        if the token resource has a default scope.
        """
        defaultScope = ['default', 'scope']
        accessToken = 'clientCredentialsAccessTokenWithoutScope'
        tokenResource = TokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, defaultScope=defaultScope)
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'client_credentials',
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(
            accessToken, tokenResource.authTokenLifeTime, self._VALID_CLIENT, defaultScope)
        result = tokenResource.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(request, result, accessToken, tokenResource.authTokenLifeTime,
                                      expectedScope=defaultScope)

    def testAuthorizedClientWithoutScopeNoDefault(self):
        """
        Test the rejection of a request without a scope
        when the token resource has no default scope.
        """
        request = self.generateValidTokenRequest(arguments={'grant_type': 'client_credentials'},
                                                 authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('scope'),
            msg='Expected the resource token to reject a client_credentials request '
                'without a scope when no default scope is given.')

    def testAuthorizedClientWithScope(self):
        """ Test that a valid request is accepted. """
        accessToken = 'clientCredentialsAccessToken'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'client_credentials',
            'scope': ' '.join(self._VALID_SCOPE),
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                                               self._VALID_CLIENT, self._VALID_SCOPE)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(
            request, result, accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedScope=self._VALID_SCOPE)

    def testAuthorizedClientWithMalformedScope(self):
        """ Test the rejection of a request with a malformed scope parameters. """
        malformedScope = b'malformedScope\xFF\xFF'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'client_credentials',
            'scope': malformedScope,
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidScopeError(malformedScope),
            msg='Expected the resource token to reject a '
                'client_credentials request with a malformed scope parameters.')

    def testAuthorizedClientWithMultipleScope(self):
        """ Test the rejection of a request with multiple scope parameters. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'client_credentials',
            'scope': self._VALID_SCOPE,
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MultipleParameterError('scope'),
            msg='Expected the resource token to reject a '
                'client_credentials request with multiple scope parameters.')
