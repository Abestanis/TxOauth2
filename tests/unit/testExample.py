""" Tests for the example. """

import os
import sys
import re
import json
import importlib
import warnings

from txoauth2.errors import InvalidScopeError, UserDeniesAuthorization
from txoauth2.token import TokenResource

from tests import MockSite, MockRequest, TwistedTestCase
from tests.unit.testOAuth2Resource import AbstractAuthResourceTest
from tests.unit.testTokenResource import AbstractTokenResourceTest


class FullExampleTestCase(TwistedTestCase):
    """
    Test case that tests that the OAuth2 specification is respected by applying
    the routines specified by the specification to the example server.
    """
    _VALID_TOKEN = 'validAuthToken'
    _VALID_SCOPE = ['VIEW_CLOCK']

    @classmethod
    def setUpClass(cls):
        super(FullExampleTestCase, cls).setUpClass()
        sys.path.append(os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', '..', 'example')))
        exampleModule = importlib.import_module('main')
        cls._VALID_CLIENT = exampleModule.getTestClient()
        cls._SERVER = MockSite(exampleModule.setupTestServerResource())
        TokenResource.getTokenStorageSingleton().store(
            cls._VALID_TOKEN, cls._VALID_CLIENT, cls._VALID_SCOPE)

    @classmethod
    def tearDownClass(cls):
        setattr(TokenResource, '_OAuthTokenStorage', None)

    def _makeExampleRequest(self, request):
        """
        Make a request to the example server and ensure that there is no warning raised.

        :param request: The request to make.
        """
        with warnings.catch_warnings(record=True) as caughtWarnings:
            warnings.simplefilter('always')
            self._SERVER.makeSynchronousRequest(request)
            self.assertEqual(0, len(caughtWarnings),
                             msg='Expected the example OAuth2 resource not to generate a warning.')

    def _doAuthorizationRequest(self, state):
        """
        Make an authorization request to the authorization resource.

        :param state: The state to send with the request.
        :return: The data key that was generated by the authorization resource.
        """
        request = AbstractAuthResourceTest.createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': ' '.join(self._VALID_SCOPE),
            'state': state
        })
        self._makeExampleRequest(request)
        self.assertIn(
            request.responseCode, (None, 200),
            msg='Expected the auth resource to accept a valid request.')
        response = request.getResponse()
        self.assertSubstring(
            b'<!DOCTYPE html>', response,
            msg='Expected the auth resource to send the content returned by onAuthenticate.')
        return re.search(b"<input.*name=\"data_key\".*value=\"(?P<dataKey>.*)\">", response) \
            .group('dataKey')

    def _testValidAccessRequest(self, token=_VALID_TOKEN):
        """
        Test that a request to the protected resource with the given token is accepted.
        :param token: The token to use in the request.
        """
        request = MockRequest('GET', 'clock')
        request.setRequestHeader(b'Authorization', 'Bearer ' + token)
        self._makeExampleRequest(request)
        self.assertIn(
            request.responseCode, (None, 200),
            msg='Expected the protected clock resource to accept a request with a valid token.')
        self.assertSubstring(
            b'<html><body>', request.getResponse(),
            msg='Expected the protected clock resource to send the protected content.')

    def testAccessClockResourceWithoutToken(self):
        """ Test that a request to the protected resource with an invalid token is rejected. """
        request = MockRequest('GET', 'clock')
        self._makeExampleRequest(request)
        self.assertEqual(401, request.responseCode, msg='Expected the protected clock resource '
                                                        'to reject a request without a token.')
        self.assertNotSubstring(b'<html><body>', request.getResponse(),
                                msg='Expected the protected clock resource '
                                    'not to send the protected content.')

    def testAccessClockResourceWithValidToken(self):
        """ Test that a request to the protected resource with a valid token is accepted. """
        self._testValidAccessRequest()

    def testAuthorizationInvalidScope(self):
        """ Test that a authorization request with an invalid scope is rejected. """
        scope = self._VALID_SCOPE + ['INVALID']
        state = b'state'
        request = AbstractAuthResourceTest.createAuthRequest(arguments={
            'response_type': 'code',
            'client_id': self._VALID_CLIENT.id,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
            'scope': ' '.join(scope),
            'state': state
        })
        self._makeExampleRequest(request)
        expectedError = InvalidScopeError(scope, state)
        self.assertEqual(302, request.responseCode,
                         msg='Expected the auth resource to redirect the request.')
        redirectUrl = request.getResponseHeader(b'location')
        self.assertIsNotNone(redirectUrl, msg='Expected the auth resource to redirect the request.')
        parameter = AbstractAuthResourceTest.getParameterFromRedirectUrl(redirectUrl, False)
        self.assertIn('error', parameter, msg='Missing error parameter in response.')
        self.assertEqual(expectedError.name, parameter['error'],
                         msg='Result contained a different error than expected.')
        self.assertIn('error_description', parameter,
                      msg='Missing error_description parameter in response.')
        if not isinstance(expectedError.description, (bytes, str)):
            self.assertEqual(
                expectedError.description.encode('utf-8'), parameter['error_description'],
                msg='Result contained a different error description than expected.')
        else:
            self.assertEqual(
                expectedError.description, parameter['error_description'],
                msg='Result contained a different error description than expected.')
        if expectedError.errorUri is not None:
            self.assertIn('error_uri', parameter,
                          msg='Missing error_uri parameter in response.')
            self.assertEqual(expectedError.errorUri, parameter['error_uri'],
                             msg='Result contained an unexpected error_uri.')
        self.assertIn('state', parameter, msg='Missing state parameter in response.')
        self.assertEqual(
            expectedError.state if isinstance(expectedError.state, str)
            else expectedError.state.decode('utf-8', errors='replace'), parameter['state'],
            msg='Result contained an unexpected state.')

    def testAuthorizationCodeGrantDeny(self):
        """ Test the authorization code grant flow when the user denies. """
        state = b'state'
        dataKey = self._doAuthorizationRequest(state)
        request = MockRequest('POST', 'oauth2', arguments={
            'confirm': 'no',
            'data_key': dataKey
        })
        self._makeExampleRequest(request)
        self.assertEqual(302, request.responseCode,
                         msg='Expected the auth resource to redirect the request.')
        redirectUrl = request.getResponseHeader(b'location')
        self.assertIsNotNone(redirectUrl, msg='Expected the auth resource to redirect the request.')
        parameter = AbstractAuthResourceTest.getParameterFromRedirectUrl(redirectUrl, False)
        self.assertIn('error', parameter, msg='Missing error parameter in response.')
        self.assertEqual(
            UserDeniesAuthorization().name, parameter['error'],
            msg='Result contained an unexpected error.')
        self.assertIn('state', parameter, msg='Missing state parameter in response.')
        self.assertEqual(
            state if isinstance(state, str) else state.decode('utf-8', errors='replace'),
            parameter['state'], msg='Result contained an unexpected state.')

    def testAuthorizationCodeGrant(self):
        """ Test the authorization code grant flow. """
        state = b'state'
        dataKey = self._doAuthorizationRequest(state)
        request = MockRequest('POST', 'oauth2', arguments={
            'confirm': 'yes',
            'data_key': dataKey
        })
        self._makeExampleRequest(request)
        self.assertEqual(302, request.responseCode,
                         msg='Expected the auth resource to redirect the request.')
        redirectUrl = request.getResponseHeader(b'location')
        self.assertIsNotNone(redirectUrl, msg='Expected the auth resource to redirect the request.')
        parameter = AbstractAuthResourceTest.getParameterFromRedirectUrl(redirectUrl, False)
        self.assertIn('code', parameter, msg='Missing code parameter in response.')
        self.assertIn('state', parameter, msg='Missing state parameter in response.')
        self.assertEqual(
            state if isinstance(state, str) else state.decode('utf-8', errors='replace'),
            parameter['state'], msg='Result contained an unexpected state.')
        code = parameter['code']
        request = AbstractTokenResourceTest.generateValidTokenRequest(arguments={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self._VALID_CLIENT.redirectUris[0],
        }, url='oauth2/token', authentication=self._VALID_CLIENT)
        self._makeExampleRequest(request)
        self.assertEqual(200, request.responseCode,
                         msg='Expected the token resource to accept the request.')
        jsonResult = json.loads(request.getResponse().decode('utf-8'), encoding='utf-8')
        self.assertIn('access_token', jsonResult, msg='Expected the result from the token resource '
                                                      'to contain an access_token parameter.')
        self.assertIn('refresh_token', jsonResult,
                      msg='Expected the result from the token resource '
                          'to contain a refresh_token parameter.')
        self.assertIn('scope', jsonResult,
                      msg='Expected the result from the token resource '
                          'to contain a scope parameter.')
        self.assertListEqual(jsonResult['scope'].split(), self._VALID_SCOPE,
                             msg='The token resource returned a different '
                                 'scope than expected.')
        accessToken = jsonResult['access_token']
        self._testValidAccessRequest(token=accessToken)
        refreshToken = jsonResult['refresh_token']
        self._testTokenRefresh(refreshToken)

    def _testTokenRefresh(self, refreshToken):
        """ Test that one can get a new access token with the refresh token. """
        request = AbstractTokenResourceTest.generateValidTokenRequest(arguments={
            'grant_type': 'refresh_token',
            'refresh_token': refreshToken,
            'scope': ' '.join(self._VALID_SCOPE)
        }, url='oauth2/token', authentication=self._VALID_CLIENT)
        self._makeExampleRequest(request)
        self.assertEqual(200, request.responseCode,
                         msg='Expected the token resource to accept the request.')
        jsonResult = json.loads(request.getResponse().decode('utf-8'), encoding='utf-8')
        self.assertIn('access_token', jsonResult, msg='Expected the result from the token resource '
                                                      'to contain an access_token parameter.')
        self.assertIn('scope', jsonResult,
                      msg='Expected the result from the token resource '
                          'to contain a scope parameter.')
        self.assertListEqual(jsonResult['scope'].split(), self._VALID_SCOPE,
                             msg='The token resource returned a different '
                                 'scope than expected.')
        accessToken = jsonResult['access_token']
        self._testValidAccessRequest(token=accessToken)
