""" Tests for the authorization resource side of the authorization code grant flow. """

from txoauth2 import GrantTypes

from tests import MockRequest
from tests.unit.testGrant import AbstractSharedGrantTest


class TestAuthorizationCodeGrant(AbstractSharedGrantTest):
    """
    Test the authorization resource part of the Authorization Code Grant flow.
    See https://tools.ietf.org/html/rfc6749#section-4.1
    """
    _RESPONSE_TYPE = 'code'

    # pylint: disable=arguments-differ
    def assertValidCodeResponse(self, request, result, data, msg, expectedAdditionalData=None,
                                expectedScope=None, parameterInFragment=False,
                                expectedCodeDataLifetime=120):
        """
        Validate the parameters of the uri that the authorization endpoint redirected to.

        :param request: The request.
        :param result: The result of the grantAccess call.
        :param data: The data that was stored in the persistent storage.
        :param msg: The assertion message.
        :param expectedAdditionalData: Expected additional data stored alongside the code.
        :param expectedScope: The expected scope of the code.
        :param parameterInFragment: Whether or not the return parameters
                                    are in the query or fragment of the redirect uri.
        :param expectedCodeDataLifetime: The expected life time of the
                                         code stored in the persistent storage.
        :return: The redirect parameters extracted from the redirect url.
        """
        if msg.endswith('.'):
            msg = msg[:-1]
        redirectParameter = super(TestAuthorizationCodeGrant, self).assertValidCodeResponse(
            request, result, data, msg, parameterInFragment)
        self.assertIn(
            'code', redirectParameter,
            msg=msg + ': Expected the authorization resource to send a code to the redirect uri.')
        code = 'code' + redirectParameter['code']
        try:
            self.assertApproximates(
                expectedCodeDataLifetime, self._PERSISTENT_STORAGE.getExpireTime(code), 1,
                msg=msg + ': The stored code did not have the expected lifetime.')
            codeData = self._PERSISTENT_STORAGE.pop(code)
        except KeyError:
            self.fail(msg + ': Expected the authorization resource to store a data '
                            'entry with the given code in the persistent storage.')
        if expectedScope is None:
            expectedScope = data['scope']
        self.assertIn('scope', codeData, msg=msg + ': Expected the authorization resource to '
                                                   'store the scope in the code date.')
        self.assertListEqual(expectedScope, codeData['scope'],
                             msg=msg + ': Expected the authorization resource to store the '
                                       'expected scope in the code date.')
        self.assertIn('additional_data', codeData,
                      msg=msg + ': Expected the authorization resource to store the '
                                'additional data in the code date.')
        self.assertEqual(expectedAdditionalData, codeData['additional_data'],
                         msg=msg + ': Expected the authorization resource to store the '
                                   'expected additional data in the code date.')
        for key in ['client_id', 'redirect_uri']:
            self.assertIn(
                key, codeData, msg=msg + ': Expected the authorization resource to store the '
                                         '{name} in the code date.'.format(name=key))
            self.assertEqual(data[key], codeData[key],
                             msg=msg + ': Expected the authorization resource to store the '
                                       'expected {name} in the code date.'.format(name=key))
        return redirectParameter

    def testGrantAccessCodeLifetime(self):
        """ Ensure that the code lifetime is controlled by the codeDataLifetime parameter. """
        dataKey = 'authorizationCodeGrantDataKeyLifetime'
        redirectUri = self._VALID_CLIENT.redirectUris[0]
        lifeTime = 60
        request = MockRequest('GET', 'some/path')
        data = {
            'response_type': GrantTypes.AuthorizationCode.value,
            'redirect_uri': redirectUri,
            'client_id': self._VALID_CLIENT.id,
            'scope': ['All'],
            'state': b'state\xFF\xFF'
        }
        self._PERSISTENT_STORAGE.put(dataKey, data)
        result = self._AUTH_RESOURCE.grantAccess(request, dataKey, codeLifeTime=lifeTime)
        self.assertValidCodeResponse(
            request, result, data, expectedCodeDataLifetime=lifeTime,
            msg='Expected the auth resource to correctly handle a valid accepted code grant '
                'and store the code data with the given lifetime.')

    def testGrantAccessAdditionalData(self):
        """ Ensure that additional data given to grantAccess is stored with the code. """
        self._testGrantAccessAdditionalData(
            dataKey='authorizationCodeGrantDataKeyAdditionalData',
            responseType=GrantTypes.AuthorizationCode.value,
            msg='Expected the auth resource to correctly handle a valid accepted code grant '
                'and store the code data with the given additional data.')
