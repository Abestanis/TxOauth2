""" Tests for the token resource side of the authorization code grant flow. """

from txoauth2 import GrantTypes
from txoauth2.errors import UnauthorizedClientError, DifferentRedirectUriError, \
    MissingParameterError, InvalidTokenError, MultipleParameterError, InvalidParameterError, \
    ServerError

from tests import getTestPasswordClient
from tests.unit.testTokenResource import AbstractTokenResourceTest


class TestAuthorizationCodeGrant(AbstractTokenResourceTest):
    """
    Test the token resource part of the Authorization Code Grant flow.
    See https://tools.ietf.org/html/rfc6749#section-4.1
    """

    def _addAuthorizationToStorage(self, code, client, scope,
                                   redirectUri=None, additionalData=None):
        """
        Put a data entry in the persistent storage as the authorization endpoint
        would have done it for the given values.
        :param code: The authorization code.
        :param client: The client that the code authorizes.
        :param scope: The scope that the code authorizes.
        :param redirectUri: An optional redirect uri that was given in the authentication request.
        :param additionalData: Optional additional data given to 'grantAccess'.
        """
        self._PERSISTENT_STORAGE.put('code' + code, {
            'redirect_uri': redirectUri,
            'client_id': client.id,
            'scope': scope,
            'additional_data': additionalData
        })

    def _doValidTokenRequest(
            self, code, accessToken, refreshToken, requestArguments, redirectUri=None):
        """
        Make a request to the token resource and assert that the two tokens have been stored.

        :param code: The code parameter for the request.
        :param accessToken: The expected generated access token.
        :param refreshToken: The expected generated refresh token.
        :param requestArguments: Arguments for the request.
        :param redirectUri: The redirect uri that was used to get the code.
        :return: The request and the generated response.
        """
        self._addAuthorizationToStorage(
            code, self._VALID_CLIENT, self._VALID_SCOPE, redirectUri=redirectUri)
        request = self.generateValidTokenRequest(
            arguments=requestArguments, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                                               self._VALID_CLIENT, self._VALID_SCOPE)
        self._TOKEN_FACTORY.expectTokenRequest(
            refreshToken, None, self._VALID_CLIENT, self._VALID_SCOPE)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        return request, result

    def testUnauthorizedClient(self):
        """
        Test the rejection of a request with a client that is
        not authorized to use the authorization code grant type.
        """
        client = getTestPasswordClient('unauthorizedCodeGrantClient', authorizedGrantTypes=[])
        code = 'unauthorizedClientCode'
        self._addAuthorizationToStorage(code, client, ['scope'], client.redirectUris[0])
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': client.redirectUris[0],
        }, authentication=client)
        self._CLIENT_STORAGE.addClient(client)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, UnauthorizedClientError('authorization_code'),
            msg='Expected the resource token to reject an authorization_code request '
                'with a client that is not authorized to use that grant type.')

    def testDifferentRedirectUri(self):
        """
        Test the rejection of a request with a different
        redirect uri than in the authorization request.
        """
        code = 'invalidRedirectUriCode'
        self._addAuthorizationToStorage(code, self._VALID_CLIENT, ['scope'],
                                        self._VALID_CLIENT.redirectUris[0])
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'https://invalidRedirect.url',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, DifferentRedirectUriError(),
            msg='Expected the resource token to reject an authorization_code request '
                'with a different redirect uri.')

    def testMalformedRedirectUri(self):
        """ Test the rejection of a request with a malformed redirect uri. """
        code = 'malformedRedirectUriCode'
        self._addAuthorizationToStorage(code, self._VALID_CLIENT, ['scope'],
                                        self._VALID_CLIENT.redirectUris[0])
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0].encode('utf-8') + b'\xFF\xFF',
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidParameterError('redirect_uri'),
            msg='Expected the resource token to reject an authorization_code request '
                'with a malformed redirect uri.')

    def testMultipleRedirectUris(self):
        """ Test the rejection of a request with multiple redirect uris. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': 'someCode',
            'redirect_uri': self._VALID_CLIENT.redirectUris + ['https://another.redirection.url'],
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MultipleParameterError('redirect_uri'),
            msg='Expected the resource token to reject an authorization_code request '
                'with multiple redirect uris.')

    def testMissingRedirectUri(self):
        """ Test the rejection of a request without a missing redirection uri. """
        code = 'missingRedirectUriCode'
        self._addAuthorizationToStorage(code, self._VALID_CLIENT, ['scope'],
                                        self._VALID_CLIENT.redirectUris[0])
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': code,
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('redirect_uri'),
            msg='Expected the resource token to reject an authorization_code '
                'request without a redirect uri.')

    def testWithoutRedirectUri(self):
        """
        Test that a request without a redirect URI is accepted
        if no redirection URI was given to the authentication request.
        """
        code = 'withoutRedirectUriCode'
        accessToken = 'codeGrantAccessTokenWithoutRedirectUri'
        refreshToken = 'codeGrantRefreshTokenWithoutRedirectUri'
        request, result = self._doValidTokenRequest(code, accessToken, refreshToken, {
            'grant_type': 'authorization_code',
            'code': code,
        })
        self.assertValidTokenResponse(
            request, result, accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedRefreshToken=refreshToken, expectedScope=self._VALID_SCOPE)

    def testWithoutRedirectUriButInParameter(self):
        """
        Test that a request with a redirect URI is accepted even tough
        no redirection URI was given to the authentication request.
        """
        code = 'withoutRedirectUriCodeButInParameter'
        accessToken = 'codeGrantAccessTokenWithoutRedirectUriButInParameter'
        refreshToken = 'codeGrantRefreshTokenWithoutRedirectUriButInParameter'
        request, result = self._doValidTokenRequest(code, accessToken, refreshToken, {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
        })
        self.assertValidTokenResponse(
            request, result, accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedRefreshToken=refreshToken, expectedScope=self._VALID_SCOPE)

    def testWithoutCode(self):
        """ Test the rejection of a request without an authorization code. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MissingParameterError('code'),
            msg='Expected the resource token to reject an authorization_code request '
                'without an authorization code.')

    def testInvalidCode(self):
        """ Test the rejection of a request with an invalid authorization code. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': 'invalidCode',
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidTokenError('authorization code'),
            msg='Expected the resource token to reject an authorization_code request '
                'with an invalid authorization code.')

    def testMalformedCode(self):
        """ Test the rejection of a request with a malformed authorization code. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': b'malformedCode\xFF\xFF',
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidTokenError('authorization code'),
            msg='Expected the resource token to reject an authorization_code request '
                'with a malformed authorization code.')

    def testMultipleCodes(self):
        """ Test the rejection of a request with multiple authorization codes. """
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': ['code1', 'code2'],
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, MultipleParameterError('code'),
            msg='Expected the resource token to reject an authorization_code request '
                'with multiple authorization codes.')

    def testWithDifferentClient(self):
        """
        Test the rejection of a request with a valid
        authorization code that authorizes a different client.
        """
        client = getTestPasswordClient(
            'unauthorizedCodeGrantClient', authorizedGrantTypes=[GrantTypes.AuthorizationCode])
        code = 'differentClientCode'
        self._addAuthorizationToStorage(code, client, ['scope'], client.redirectUris[0])
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': client.redirectUris[0],
        }, authentication=self._VALID_CLIENT)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self.assertFailedTokenRequest(
            request, result, InvalidTokenError('authorization code'),
            msg='Expected the resource token to reject an authorization_code request '
                'with a code that was issued to a different client.')

    def testValidCode(self):
        """ Test that a request with a valid authorization code is accepted. """
        code = 'validCode'
        accessToken = 'codeGrantAccessToken'
        refreshToken = 'codeGrantRefreshToken'
        request, result = self._doValidTokenRequest(code, accessToken, refreshToken, {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
        }, redirectUri=self._VALID_CLIENT.redirectUris[0])
        self.assertValidTokenResponse(
            request, result, accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedRefreshToken=refreshToken, expectedScope=self._VALID_SCOPE)

    def testWithAdditionalData(self):
        """
        Test that any additional data passed to the 'grantAccess'
        method gets passed to the token factory and storage.
        """
        code = 'validCodeWithAdditionalData'
        accessToken = 'codeGrantAccessTokenWithAdditionalData'
        refreshToken = 'codeGrantRefreshTokenWithAdditionalData'
        additionalData = 'SomeData'
        self._addAuthorizationToStorage(code, self._VALID_CLIENT, self._VALID_SCOPE,
                                        self._VALID_CLIENT.redirectUris[0], additionalData)
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(
            accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            self._VALID_CLIENT, self._VALID_SCOPE, additionalData)
        self._TOKEN_FACTORY.expectTokenRequest(
            refreshToken, None, self._VALID_CLIENT, self._VALID_SCOPE, additionalData)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertValidTokenResponse(
            request, result, accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
            expectedRefreshToken=refreshToken, expectedScope=self._VALID_SCOPE,
            expectedAdditionalData=additionalData)

    def testTokenGeneratorGeneratesInvalidToken(self):
        """
        Test that the token resource handles the case
        when the TokenGenerator generates an invalid token.
        """
        code = 'codeInvalidTokenFromGenerator'
        accessToken = 'codeGrantAccessTokenInvalidTokenFromGenerator'
        refreshToken = 'invalidToken!'
        request, result = self._doValidTokenRequest(code, accessToken, refreshToken, {
            'grant_type': 'authorization_code',
            'code': code,
        })
        self.assertFailedTokenRequest(
            request, result, ServerError(
                message='Generated token is invalid: {token}'.format(token=refreshToken)),
            msg='Expected the resource token to generate a ServerError for an authorization_code '
                'request if the token factory generates an invalid refresh token.')
        accessToken = 'invalidToken#'
        self._addAuthorizationToStorage(code, self._VALID_CLIENT, self._VALID_SCOPE)
        request = self.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': code,
        }, authentication=self._VALID_CLIENT)
        self._TOKEN_FACTORY.expectTokenRequest(accessToken, self._TOKEN_RESOURCE.authTokenLifeTime,
                                               self._VALID_CLIENT, self._VALID_SCOPE)
        result = self._TOKEN_RESOURCE.render_POST(request)
        self._TOKEN_FACTORY.assertAllTokensRequested()
        self.assertFailedTokenRequest(
            request, result, ServerError(
                message='Generated token is invalid: {token}'.format(token=accessToken)),
            msg='Expected the resource token to generate a ServerError for an authorization_code '
                'request if the token factory generates an invalid access token.')
