from txoauth2.token import TokenResource
from txoauth2.errors import UnauthorizedClientError, MissingParameterError, InvalidTokenError, \
    MultipleParameterError, InvalidScopeError, UnsupportedGrantType

from tests import getTestPasswordClient
from tests.unit.testTokenResource import AbstractTokenResourceTest


class TestResourceOwnerPasswordCredentialsGrant(AbstractTokenResourceTest):
    """
    Test the functionality of the Resource Owner Password Credentials Grant.
    See https://tools.ietf.org/html/rfc6749#section-4.3
    """

    def testUnauthorizedClient(self):
        """
        Test the rejection of a client that is not authorized
        to use the Resource Owner Password Credentials Grant.
        """
        client = getTestPasswordClient('unauthorizedResourceOwnerPasswordCredentialsGrantClient',
                                       authorizedGrantTypes=[])
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': 'someUser',
            'password': 'somePassword',
        }, authentication=client)
        self._CLIENT_STORAGE.addClient(client)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, UnauthorizedClientError('password'),
            msg='Expected the resource token to reject a password request '
                'with a client that is not authorized to use that grant type.')

    def testMissingUserName(self):
        """ Test the rejection of a request that is missing the user name. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'password': 'somePassword'
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('username'),
            msg='Expected the resource token to reject a password request without an username.')

    def testMultipleUserNames(self):
        """ Test the rejection of a request that has multiple user names. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': ['userName1', 'userName2'],
            'password': 'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, MultipleParameterError('username'),
                                      msg='Expected the resource token to reject a password '
                                          'request with multiple user names.')

    def testInvalidUserName(self):
        """ Test the rejection of a request with an invalid user name. """
        userName = 'invalidUser'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': 'somePassword',
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(
            userName, self._PASSWORD_MANAGER.INVALID_PASSWORD)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self.assertFailedTokenRequest(request, result, InvalidTokenError('username'),
                                      msg='Expected the resource token to reject a password '
                                          'request with an invalid username.')

    def testMalformedUserName(self):
        """ Test the rejection of a request with a malformed user name. """
        userName = b'malformedUser\xFF\xFF'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': 'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, InvalidTokenError('username'),
                                      msg='Expected the resource token to reject a password '
                                          'request with a malformed username.')

    def testMissingPassword(self):
        """ Test the rejection of a request without a password. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': 'someUserName',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('password'),
            msg='Expected the resource token to reject a password request without a password.')

    def testMultiplePasswords(self):
        """ Test the rejection of a request with multiple passwords. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': 'someUserName',
            'password': ['password1', 'password2'],
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MultipleParameterError('password'),
            msg='Expected the resource token to reject a password request with multiple passwords.')

    def testInvalidPassword(self):
        """ Test the rejection of a request with an invalid password. """
        userName = 'validUserWithInvalidPassword'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': 'invalidPassword',
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(
            userName, self._PASSWORD_MANAGER.INVALID_PASSWORD)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self.assertFailedTokenRequest(request, result, InvalidTokenError('password'),
                                      msg='Expected the resource token to reject a password '
                                          'request with an invalid password.')

    def testMalformedPassword(self):
        """ Test the rejection of a request with a malformed password. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': 'someUser',
            'password': b'malformedPassword\xFF\xFF',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, InvalidTokenError('password'),
                                      msg='Expected the resource token to reject a password '
                                          'request with a malformed password.')

    def testAuthorizedWithoutScope(self):
        """
        Test that a request without a scope is accepted,
        if the token resource has a default scope.
        """
        userName = 'validUserWithoutScope'
        password = 'validPasswordWithoutScope'
        defaultScope = ['default', 'scope']
        authToken = 'resourceOwnerPasswordCredentialsTokenWithoutScope'
        tokenResource = TokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, defaultScope=defaultScope)
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'username': userName,
            'password': password,
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(userName, password)
        self._TOKEN_FACTORY.expectTokenRequest(authToken, tokenResource.authTokenLifeTime,
                                               self._VALID_CLIENT, defaultScope)
        result = tokenResource.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(
            request, result, authToken, tokenResource.authTokenLifeTime, expectedScope=defaultScope)

    def testAuthorizedWithoutScopeNoDefault(self):
        """
        Test the rejection of a request without a scope,
        if the token resource does not have a default scope.
        """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'username': 'someUser',
            'password': 'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('scope'),
            msg='Expected the resource token to reject a password request '
                'without a scope when the token resource has no default.')

    def testAuthorizedWithScope(self):
        """ Test that a valid request with a scope is accepted. """
        userName = 'validUser'
        password = 'validPassword'
        authToken = 'resourceOwnerPasswordCredentialsToken'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': password,
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(userName, password)
        self._TOKEN_FACTORY.expectTokenRequest(authToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                                               self._VALID_CLIENT, self._VALID_SCOPE)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(
            request, result, authToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedScope=self._VALID_SCOPE)

    def testMalformedScope(self):
        """ Test the rejection of a request with a malformed scope. """
        malformedScope = b'malformedScope\xFF\xFF'
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': malformedScope,
            'username': 'someUser',
            'password': 'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidScopeError(malformedScope),
            msg='Expected the resource token to reject a password request with a malformed scope.')

    def testMultipleScopes(self):
        """ Test the rejection of a request with multiple scope parameters. """
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': self._VALID_SCOPE,
            'username': 'someUser',
            'password': 'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MultipleParameterError('scope'),
            msg='Expected the resource token to reject a '
                'password request with multiple scope parameters.')

    def testWhenDisabled(self):
        """ Test the rejection of a password request when the grant type is disabled. """
        tokenResource = TokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE)
        request = self._generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'username': 'someUserName',
            'password': 'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = tokenResource.render_POST(request)
        self.assertFailedTokenRequest(request, result, UnsupportedGrantType('password'),
                                      msg='Expected the token resource to reject a password '
                                          'request, if the grant type is disabled')
