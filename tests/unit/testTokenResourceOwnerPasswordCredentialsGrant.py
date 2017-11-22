from txoauth2.token import TokenResource
from txoauth2.errors import UnauthorizedClientError, MissingParameterError, InvalidTokenError, \
    MultipleParameterError, InvalidScopeError, UnsupportedGrantTypeError

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
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': b'someUser',
            'password': b'somePassword',
        }, authentication=client)
        self._CLIENT_STORAGE.addClient(client)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, UnauthorizedClientError('password'),
            msg='Expected the resource token to reject a password request '
                'with a client that is not authorized to use that grant type.')

    def testMissingUserName(self):
        """ Test the rejection of a request that is missing the user name. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'password': b'somePassword'
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('username'),
            msg='Expected the resource token to reject a password request without an username.')

    def testMultipleUserNames(self):
        """ Test the rejection of a request that has multiple user names. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': [b'userName1', b'userName2'],
            'password': b'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(request, result, MultipleParameterError('username'),
                                      msg='Expected the resource token to reject a password '
                                          'request with multiple user names.')

    def testInvalidUserName(self):
        """ Test the rejection of a request with an invalid user name. """
        userName = b'invalidUser'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': b'somePassword',
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(
            userName, self._PASSWORD_MANAGER.INVALID_PASSWORD)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self.assertFailedTokenRequest(request, result, InvalidTokenError('username or password'),
                                      msg='Expected the resource token to reject a password '
                                          'request with an invalid username.')

    def testMalformedUserName(self):
        """ Test the rejection of a request with a malformed user name. """
        userName = b'malformedUser\xFF\xFF'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': b'somePassword',
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(
            userName, self._PASSWORD_MANAGER.INVALID_PASSWORD)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self.assertFailedTokenRequest(request, result, InvalidTokenError('username or password'),
                                      msg='Expected the resource token to reject a password '
                                          'request with a malformed username.')

    def testMissingPassword(self):
        """ Test the rejection of a request without a password. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': b'someUserName',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('password'),
            msg='Expected the resource token to reject a password request without a password.')

    def testMultiplePasswords(self):
        """ Test the rejection of a request with multiple passwords. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': b'someUserName',
            'password': [b'password1', b'password2'],
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MultipleParameterError('password'),
            msg='Expected the resource token to reject a password request with multiple passwords.')

    def testInvalidPassword(self):
        """ Test the rejection of a request with an invalid password. """
        userName = b'validUserWithInvalidPassword'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': b'invalidPassword',
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(
            userName, self._PASSWORD_MANAGER.INVALID_PASSWORD)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self.assertFailedTokenRequest(request, result, InvalidTokenError('username or password'),
                                      msg='Expected the resource token to reject a password '
                                          'request with an invalid password.')

    def testMalformedPassword(self):
        """ Test the rejection of a request with a malformed password. """
        userName = b'someUser'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': b'malformedPassword\xFF\xFF',
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(
            userName, self._PASSWORD_MANAGER.INVALID_PASSWORD)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self.assertFailedTokenRequest(request, result, InvalidTokenError('username or password'),
                                      msg='Expected the resource token to reject a password '
                                          'request with a malformed password.')

    def testAuthorizedWithoutScope(self):
        """
        Test that a request without a scope is accepted,
        if the token resource has a default scope.
        """
        userName = b'validUserWithoutScope'
        password = b'validPasswordWithoutScope'
        defaultScope = ['default', 'scope']
        authToken = 'resourceOwnerPasswordCredentialsTokenWithoutScope'
        refreshToken = 'resourceOwnerPasswordCredentialsRefreshTokenWithoutScope'
        tokenResource = TokenResource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._REFRESH_TOKEN_STORAGE,
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, defaultScope=defaultScope,
            passwordManager=self._PASSWORD_MANAGER)
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'username': userName,
            'password': password,
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(userName, password)
        self._TOKEN_FACTORY.expectTokenRequest(
            authToken, tokenResource.authTokenLifeTime, self._VALID_CLIENT, defaultScope)
        self._TOKEN_FACTORY.expectTokenRequest(refreshToken, None, self._VALID_CLIENT, defaultScope)
        result = tokenResource.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(request, result, authToken, tokenResource.authTokenLifeTime,
                                      expectedScope=defaultScope, expectedRefreshToken=refreshToken)

    def testAuthorizedWithoutScopeNoDefault(self):
        """
        Test the rejection of a request without a scope,
        if the token resource does not have a default scope.
        """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'username': b'someUser',
            'password': b'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('scope'),
            msg='Expected the resource token to reject a password request '
                'without a scope when the token resource has no default.')

    def testAuthorizedWithScope(self):
        """ Test that a valid request with a scope is accepted. """
        userName = b'validUser'
        password = b'validPassword'
        authToken = 'resourceOwnerPasswordCredentialsToken'
        refreshToken = 'resourceOwnerPasswordCredentialsRefreshToken'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': ' '.join(self._VALID_SCOPE),
            'username': userName,
            'password': password,
        }, authentication=self._VALID_CLIENT)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(userName, password)
        self._TOKEN_FACTORY.expectTokenRequest(authToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                                               self._VALID_CLIENT, self._VALID_SCOPE)
        self._TOKEN_FACTORY.expectTokenRequest(
            refreshToken, None, self._VALID_CLIENT, self._VALID_SCOPE)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given '
                            'user name and password combination is valid.')
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(
            request, result, authToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedScope=self._VALID_SCOPE, expectedRefreshToken=refreshToken)

    def testMalformedScope(self):
        """ Test the rejection of a request with a malformed scope. """
        malformedScope = b'malformedScope\xFF\xFF'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': malformedScope,
            'username': b'someUser',
            'password': b'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidScopeError(malformedScope),
            msg='Expected the resource token to reject a password request with a malformed scope.')

    def testMultipleScopes(self):
        """ Test the rejection of a request with multiple scope parameters. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'scope': self._VALID_SCOPE,
            'username': b'someUser',
            'password': b'somePassword',
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
            self._AUTH_TOKEN_STORAGE, self._CLIENT_STORAGE, grantTypes=[])
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'username': b'someUserName',
            'password': b'somePassword',
        }, authentication=self._VALID_CLIENT)
        result = tokenResource.render_POST(request)
        self.assertFailedTokenRequest(request, result, UnsupportedGrantTypeError('password'),
                                      msg='Expected the token resource to reject a password '
                                          'request, if the grant type is disabled')

    def testInvalidScope(self):
        """ Test the rejection of a request with an invalid scope parameters. """
        username = b'someUserName'
        password = b'somePassword'
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'password',
            'username': username,
            'password': password,
            'scope': ' '.join(self._VALID_SCOPE),
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(
            'token', self._TOKEN_RESOURCE.authTokenLifeTime, self._VALID_CLIENT,
            self._VALID_SCOPE, validScope=False)
        self._PASSWORD_MANAGER.expectAuthenticateRequest(username, password)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertTrue(self._PASSWORD_MANAGER.allPasswordsChecked(),
                        msg='Expected the token resource to check if the given user name and '
                            'password combination is valid before creating an auth token.')
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertFailedTokenRequest(
            request, result, InvalidScopeError(self._VALID_SCOPE),
            msg='Expected the resource token to reject a '
                'password request with invalid scope parameters.')
