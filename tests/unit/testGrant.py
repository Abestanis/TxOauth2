""" Abstract tests for the grant types supported by the authorization resource. """

from txoauth2 import GrantTypes
from txoauth2.clients import PublicClient
from txoauth2.errors import UnauthorizedClientError, MissingParameterError, InvalidParameterError, \
    MalformedParameterError, MultipleParameterError, InvalidRedirectUriError, InvalidScopeError, \
    UnsupportedResponseTypeError, UserDeniesAuthorization, InsecureConnectionError
from txoauth2.resource import InsecureRedirectUriError

from tests import getTestPasswordClient, MockRequest
from tests.unit.testOAuth2Resource import AbstractAuthResourceTest


class AbstractSharedGrantTest(AbstractAuthResourceTest):  # pylint: disable=too-many-public-methods
    """
    This test contains test for shared functionality for
    the grant types that use the authentication resource.
    """
    _RESPONSE_TYPE = None

    def assertValidCodeResponse(self, request, result, data, msg,
                                expectedAdditionalData=None, expectedScope=None, **kwargs):
        """
        Validate the parameters of the uri that the authorization endpoint redirected to.

        :param request: The request.
        :param result: The result of the grantAccess call.
        :param data: The data that was stored in the persistent storage.
        :param msg: The assertion message.
        :param expectedAdditionalData: Expected additional data stored alongside the code.
        :param expectedScope: The expected scope of the code.
        :param kwargs: Additional keyword arguments.
        """
        raise NotImplementedError()

    def assertFailedRequest(self, request, result, expectedError, msg=None, redirectUri=None,
                            parameterInFragment=None):
        """
        Assert that the request did not succeed and that
        the auth resource returned an appropriate error response.
        :param request: The request.
        :param result: The return value of the render_POST function of the token resource.
        :param expectedError: The expected error.
        :param msg: The assertion error message.
        :param redirectUri: The redirect uri of the client.
        :param parameterInFragment: If the error parameters are in the fragment of the redirect uri.
                                    If None, use the default for the response type.
        """
        if parameterInFragment is None:
            parameterInFragment = self._RESPONSE_TYPE == 'token'
        super(AbstractSharedGrantTest, self).assertFailedRequest(
            request, result, expectedError, msg, redirectUri, parameterInFragment)

    def testWithUnauthorizedClient(self):
        """
        Test the rejection of a request with a client
        that is not allowed to use the response type.
        """
        state = b'state\xFF\xFF'
        client = getTestPasswordClient(authorizedGrantTypes=[])
        redirectUri = client.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': client.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        self._CLIENT_STORAGE.addClient(client)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, UnauthorizedClientError(self._RESPONSE_TYPE, state=state),
            msg='Expected the auth resource to reject a request for a client that is not '
                'authorized to request an authorization using the '
                '{type} method.'.format(type=self._RESPONSE_TYPE), redirectUri=redirectUri)

    def testWithoutClientId(self):
        """ Test the rejection of a request without a client id. """
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MissingParameterError('client_id'),
            msg='Expected the auth resource to reject a request without a client id.')

    def testWithInvalidClientId(self):
        """ Test the rejection of a request with an invalid client id. """
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': 'invalidClientId',
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InvalidParameterError('client_id'),
            msg='Expected the auth resource to reject a request with an invalid client id.')

    def testWithMalformedClientId(self):
        """ Test the rejection of a request with a malformed client id. """
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': b'malformedClientId\xFF\xFF',
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MalformedParameterError('client_id'),
            msg='Expected the auth resource to reject a request with a malformed client id.')

    def testWithMultipleClientIds(self):
        """ Test the rejection of a request with multiple client ids. """
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': [self._VALID_CLIENT.id] * 2,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MultipleParameterError('client_id'),
            msg='Expected the auth resource to reject a request with multiple client ids.')

    def testWithoutRedirectUriButClientHasOne(self):
        """
        Test that a request without a redirect uri is accepted
        if the client has ony one predefined redirect uri.
        """
        client = PublicClient(
            'clientWithOneRedirectUri', self._VALID_CLIENT.redirectUris[:1],
            [GrantTypes.AuthorizationCode.value, GrantTypes.Implicit.value])
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': client.id,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        }
        self._CLIENT_STORAGE.addClient(client)
        request = self.createAuthRequest(arguments=parameter)
        result = self._AUTH_RESOURCE.render_GET(request)
        parameter['redirect_uri'] = client.redirectUris[0]
        self.assertValidAuthRequest(request, result, parameter,
                                    msg='Expected the auth resource to accept a request '
                                        'without a redirect uri if the client has one.')

    def testWithoutRedirectUriButClientHasMultiple(self):
        """
        Test the rejection of a request without a redirect uri
        if the client has more than one predefined redirect uri.
        """
        client = PublicClient('clientWithMultipleRedirectUris', ['https://return.nonexistent'] * 2,
                              ['authorization_code'])
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': client.id,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        self._CLIENT_STORAGE.addClient(client)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MissingParameterError('redirect_uri'),
            msg='Expected the auth resource to reject a request without a redirect uri.')

    def testWithInvalidRedirectUri(self):
        """ Test the rejection of a request with an invalid redirect uri. """
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': 'invalidRedirectUri',
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InvalidRedirectUriError(),
            msg='Expected the auth resource to reject a request with an invalid redirect uri.')

    def testWithMalformedRedirectUri(self):
        """ Test the rejection of a request with a malformed redirect uri. """
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': b'malformedRedirectUri\xFF\xFF',
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MalformedParameterError('redirect_uri'),
            msg='Expected the auth resource to reject a request with a malformed redirect uri.')

    def testWithMultipleRedirectUris(self):
        """ Test the rejection of a request with multiple redirect uris. """
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': [self._VALID_CLIENT.redirectUris[0]] * 2,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MultipleParameterError('redirect_uri'),
            msg='Expected the auth resource to reject a request with multiple redirect uris.')

    def testWithoutScope(self):
        """ Test that a request without a scope is accepted if a default scope is defined. """
        defaultScope = 'default'
        authToken = AbstractAuthResourceTest.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            defaultScope=[defaultScope], authTokenStorage=self._TOKEN_STORAGE)
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'state': b'state\xFF\xFF'
        }
        request = self.createAuthRequest(arguments=parameter)
        result = authToken.render_GET(request)
        parameter['scope'] = defaultScope
        self.assertValidAuthRequest(request, result, parameter,
                                    msg='Expected the auth resource to accept a request without '
                                        'a scope if the auth resource has a valid scope.')

    def testWithoutScopeNoDefault(self):
        """ Test the rejection of a request without a scope if no default scope is defined. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MissingParameterError('scope', state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to reject a request without a scope.')

    def testWithMalformedScope(self):
        """ Test the rejection of a request with a malformed scope. """
        state = b'state\xFF\xFF'
        scope = b'malformedScope\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': scope,
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, InvalidScopeError(scope, state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to reject a request with a malformed scope.')

    def testWithMultipleScopes(self):
        """ Test the rejection of a request with multiple scopes. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': ['scope1', 'scope2'],
            'state': state
        })
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertFailedRequest(
            request, result, MultipleParameterError('scope', state=state), redirectUri=redirectUri,
            msg='Expected the auth resource to reject a request with a multiple scopes.')

    def testWithoutState(self):
        """ Test that a request without a state is accepted. """
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All'
        }
        request = self.createAuthRequest(arguments=parameter)
        result = self._AUTH_RESOURCE.render_GET(request)
        parameter['state'] = None
        self.assertValidAuthRequest(
            request, result, parameter,
            msg='Expected the auth resource to accept a request without a state.')

    def testWithState(self):
        """ Test that a request with a state is accepted. """
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'someState'
        }
        request = self.createAuthRequest(arguments=parameter)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameter,
            msg='Expected the auth resource to accept a request with a state.')

    def testWithNonUnicodeState(self):
        """ Test that a request with a non unicode state is accepted. """
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'someStateNotUnicode\xFF\xFF'
        }
        request = self.createAuthRequest(arguments=parameter)
        result = self._AUTH_RESOURCE.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameter,
            msg='Expected the auth resource to accept a request with a non unicode state.')

    def testWhenDisabled(self):
        """ Test the rejection of a request when the return type is disabled. """
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = self.createAuthRequest(arguments={
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': redirectUri,
            'scope': 'All',
            'state': state
        })
        authResource = AbstractAuthResourceTest.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE, grantTypes=[])
        result = authResource.render_GET(request)
        self.assertFailedRequest(
            request, result, UnsupportedResponseTypeError(self._RESPONSE_TYPE, state),
            msg='Expected the auth resource to reject a request for the {type} response type '
                'if it is not enabled.'.format(type=self._RESPONSE_TYPE), redirectUri=redirectUri)

    def testDataLifetime(self):
        """
        Test that the lifetime of the data stored by render_GET
        is controlled by the requestDataLifeTime parameter.
        """
        lifetime = 10
        parameter = {
            'response_type': self._RESPONSE_TYPE,
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': 'All',
            'state': b'state\xFF\xFF'
        }
        request = self.createAuthRequest(arguments=parameter)
        authResource = AbstractAuthResourceTest.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            requestDataLifeTime=lifetime, authTokenStorage=self._TOKEN_STORAGE)
        result = authResource.render_GET(request)
        self.assertValidAuthRequest(
            request, result, parameter,
            msg='Expected the auth resource to accept a request without a redirect uri '
                'if the client has one.', expectedDataLifetime=lifetime)

    def testDenyAccess(self):
        """ Test that denyAccess redirects with the expected error. """
        dataKey = 'userDenies_' + self._RESPONSE_TYPE
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        self._PERSISTENT_STORAGE.put(dataKey, {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': 'All',
            'state': state
        })
        request = MockRequest('GET', 'some/path')
        result = self._AUTH_RESOURCE.denyAccess(request, dataKey)
        self.assertFailedRequest(
            request, result, UserDeniesAuthorization(state), redirectUri=redirectUri,
            msg='Expected denyAccess to redirect the resource owner to the '
                'redirection endpoint with an access denied error.')

    def testGrantAccessInsecureRedirectUri(self):
        """ Test that grandAccess raises InsecureRedirectUriError for an insecure redirect uri. """
        dataKey = 'insecureRedirectUriDataKey' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[1]
        self.assertTrue(redirectUri.startswith('http://'), msg='The redirect uri is not insecure.')
        request = MockRequest('GET', 'some/path')
        self._PERSISTENT_STORAGE.put(dataKey, {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': 'All',
            'state': b'state\xFF\xFF'
        })
        self.assertRaises(InsecureRedirectUriError, self._AUTH_RESOURCE.grantAccess,
                          request, dataKey)
        try:
            self.assertEqual(self._AUTH_RESOURCE.requestDataLifetime,
                             self._PERSISTENT_STORAGE.getExpireTime(dataKey),
                             msg='Expected the data to be stored with the expected lifetime.')
            self._PERSISTENT_STORAGE.pop(dataKey)
        except KeyError:
            self.fail('Expected the data to still be in the persistent storage.')

    def testGrantAccessInsecureConnection(self):
        """
        Test that grandAccess returns the expected error for a request over an insecure transport.
        """
        dataKey = 'insecureConnectionDataKey' + self._RESPONSE_TYPE
        request = MockRequest('GET', 'some/path', isSecure=False)
        state = b'state\xFF\xFF'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        self._PERSISTENT_STORAGE.put(dataKey, {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': 'All',
            'state': state
        })
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey)
        self.assertFailedRequest(
            request, result, InsecureConnectionError(state), redirectUri=redirectUri,
            msg='Expected the authorization resource to '
                'reject a request over an insecure transport.')

    def testGrantAccessInvalidScope(self):
        """ Test that grandAccess rejects a call with a scope that is not in the original scope. """
        dataKey = 'dataKeyInvalidScope' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path')
        state = b'state\xFF\xFF'
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': state
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        scope = ['Other']
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey, scope=scope)
        self.assertFailedRequest(
            request, result, InvalidScopeError(scope, state), redirectUri=redirectUri,
            msg='Expected grantAccess to reject an invalid scope.')

    def testGrantAccessInvalidClientId(self):
        """ Test that grandAccess rejects a call with an invalid clientId. """
        dataKey = 'dataKeyInvalidClientId' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path')
        state = b'state\xFF\xFF'
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': 'invalidClientId',
            'scope': ['All'],
            'state': state
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey)
        self.assertFailedRequest(
            request, result, InvalidParameterError('client_id', state=state),
            redirectUri=redirectUri, msg='Expected grantAccess to reject an invalid client id.')

    def testGrantAccess(self):
        """ Test that grandAccess redirects with the expected parameters. """
        dataKey = 'dataKey' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path')
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': b'state\xFF\xFF'
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey)
        self.assertValidCodeResponse(
            request, result, data,
            msg='Expected the auth resource to correctly handle a valid '
                'accepted {type} grant.'.format(type=self._RESPONSE_TYPE))

    def testGrantAccessInsecureRedirectUriAllowed(self):
        """
        Test that grandAccess accepts a call with an insecure
        redirect uri if it is allowed.
        """
        dataKey = 'insecureRedirectUriDataKey' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[1]
        self.assertTrue(redirectUri.startswith('http://'), msg='The redirect uri is not insecure.')
        request = MockRequest('GET', 'some/path')
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': b'state\xFF\xFF'
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey, allowInsecureRedirectUri=True)
        self.assertValidCodeResponse(
            request, result, data,
            msg='Expected the auth resource to correctly handle a valid accepted {type} grant '
                'with an insecure redirect uri, if it is allowed.'.format(type=self._RESPONSE_TYPE))

    def testGrantAccessInsecureConnectionAllowed(self):
        """
        Test that grandAccess accepts a call with a
        request over an insecure transport if it is allowed.
        """
        dataKey = 'insecureConnectionDataKey' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path', isSecure=False)
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': b'state\xFF\xFF'
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        authResource = AbstractAuthResourceTest.TestOAuth2Resource(
            self._TOKEN_FACTORY, self._PERSISTENT_STORAGE, self._CLIENT_STORAGE,
            authTokenStorage=self._TOKEN_STORAGE, allowInsecureRequestDebug=True)
        result = authResource.grantAccess(request, dataKey)
        self.assertValidCodeResponse(
            request, result, data,
            msg='Expected the auth resource to correctly handle a valid '
                'accepted {type} grant request over an insecure transport, '
                'if it is allowed.'.format(type=self._RESPONSE_TYPE))

    def testGrantAccessSubsetScope(self):
        """ Test that grandAccess accepts a call with a subset of the original scope. """
        dataKey = 'dataKeySubsetScope' + self._RESPONSE_TYPE
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        request = MockRequest('GET', 'some/path')
        data = {
            'response_type': self._RESPONSE_GRANT_TYPE_MAPPING[self._RESPONSE_TYPE],
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All', 'Other'],
            'state': b'state\xFF\xFF'
        }
        scope = ['Other']
        self._PERSISTENT_STORAGE.put(dataKey, data)
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey, scope=scope)
        self.assertValidCodeResponse(
            request, result, data, expectedScope=scope,
            msg='Expected the auth resource to correctly handle a valid accepted {type} grant '
                'with a subset of the scope original requested.'.format(type=self._RESPONSE_TYPE))
