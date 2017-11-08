import time

from txoauth2.imp import DictTokenStorage

from tests import TwistedTestCase, getDummyClient


class AbstractTokenStorageTest(TwistedTestCase):
    """
    An abstract test case for TokenStorage implementations. A subclass must set __test__
    to True and call setupTokenStorage with an instance of the token storage to test.
    """
    _TOKEN_STORAGE = None
    _VALID_TOKEN = 'ValidToken'
    _VALID_SCOPE = ['All', 'Scope1']
    _VALID_ADDITIONAL_DATA = 'additionalData'
    _DUMMY_CLIENT = getDummyClient()

    @classmethod
    def setupTokenStorage(cls, tokenStorage, client=_DUMMY_CLIENT):
        """
        Set the token storage implementation to use for the tests
        and store the valid token in the token storage.
        :param tokenStorage: The token storage implementation to test.
        :param client: The client to use for storing tokens.
        """
        cls._TOKEN_STORAGE = tokenStorage
        cls._DUMMY_CLIENT = client
        tokenStorage.store(cls._VALID_TOKEN, client, cls._VALID_SCOPE, cls._VALID_ADDITIONAL_DATA)

    def testContains(self):
        """ Test that the token storage correctly reports if it contains a token or not. """
        self.assertTrue(self._TOKEN_STORAGE.contains(self._VALID_TOKEN),
                        msg='Expected contains to return True for a token '
                            'that was previously stored in the token storage.')
        self.assertFalse(self._TOKEN_STORAGE.contains('someInvalidToken'),
                         msg='Expected contains to return False for a token '
                             'that is not in the token storage.')

    def testHasAccess(self):
        """
        Test that the token storage only reports granted access for valid tokens
        within valid scopes or subsets of the valid scopes.
        """
        self.assertTrue(self._TOKEN_STORAGE.hasAccess(self._VALID_TOKEN, self._VALID_SCOPE),
                        msg='Expected hasAccess to return True for a valid token and scope.')
        self.assertTrue(self._TOKEN_STORAGE.hasAccess(self._VALID_TOKEN, self._VALID_SCOPE[0:1]),
                        msg='Expected hasAccess to return True for a valid token '
                            'and a subset of the valid scopes.')
        self.assertFalse(self._TOKEN_STORAGE.hasAccess(self._VALID_TOKEN, ['invalidScope']),
                         msg='Expected hasAccess to return False '
                             'for a valid token and an invalid scope.')
        self.assertFalse(
            self._TOKEN_STORAGE.hasAccess(self._VALID_TOKEN, [self._VALID_SCOPE[0].upper()]),
            msg='Expected hasAccess to return False for a valid token '
                'and an invalid scope (scopes must be case sensitive).')
        self.assertFalse(
            self._TOKEN_STORAGE.hasAccess(self._VALID_TOKEN, self._VALID_SCOPE + ['invalidScope']),
            msg='Expected hasAccess to return False for a valid token and an invalid scope.')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.hasAccess,
                          'invalidToken', self._VALID_SCOPE)

    def testGetTokenData(self):
        """
        Test that the token storage returns exactly the scope and additional data
        of a token that it was given when the token was stored.
        """
        self.assertEqual((self._VALID_SCOPE, self._VALID_ADDITIONAL_DATA),
                         self._TOKEN_STORAGE.getTokenData(self._VALID_TOKEN),
                         msg='Expected getTokenData to return the correct '
                             'scope and additional data for the token')
        token = 'otherValidToken'
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE[0:1])
        scope, data = self._TOKEN_STORAGE.getTokenData(token)
        self.assertEquals(self._VALID_SCOPE[0:1], scope,
                          msg='Expected getTokenData to return the scope given to store.')
        self.assertIsNone(data, msg='Expected getTokenData to return None if a valid token '
                                    'has not stored any additional data')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenData, 'invalidToken')

    def testStore(self):
        """
        Test that the token storage can correctly store
        a token, it's scope and it's additional data.
        """
        token = 'testToken'
        self.assertFalse(self._TOKEN_STORAGE.contains(token),
                         msg='Did expect that the token storage would not '
                             'contain the test token before it was stored.')
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE)
        self.assertTrue(self._TOKEN_STORAGE.contains(token),
                        msg='Expected the token storage to contain the token after it was stored.')
        self.assertTrue(self._TOKEN_STORAGE.hasAccess(token, self._VALID_SCOPE),
                        msg='Expected the token storage to contain the token after it was stored.')
        self.assertEquals((self._VALID_SCOPE, None), self._TOKEN_STORAGE.getTokenData(token),
                          msg='Expected the token storage return None as the additional data '
                              'for a token if none was supplied to store.')
        self.assertRaises(ValueError, self._TOKEN_STORAGE.store,
                          None, self._DUMMY_CLIENT, self._VALID_SCOPE)
        self.assertRaises(ValueError, self._TOKEN_STORAGE.store,
                          42, self._DUMMY_CLIENT, self._VALID_SCOPE)

    def testTokenOverwrite(self):
        """
        Test that the token storage correctly overwrites an existing token.
        Note that this should not happen if the TokenFactory is implemented correctly.
        """
        token = 'overwriteTestToken'
        tokenData = 'token data'
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE)
        self.assertEquals((self._VALID_SCOPE, None), self._TOKEN_STORAGE.getTokenData(token),
                          msg='Expected getTokenData to return the scope '
                              'and the additional data stored with the token.')
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE[0:1],
                                  additionalData=tokenData)
        self.assertEquals(
            (self._VALID_SCOPE[0:1], tokenData), self._TOKEN_STORAGE.getTokenData(token),
            msg='Expected getTokenData to return the new scope '
                'and new the additional data stored with the token.')
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE[1:2])
        self.assertEquals((self._VALID_SCOPE[1:2], None), self._TOKEN_STORAGE.getTokenData(token),
                          msg='Expected getTokenData to return the new scope and no additional '
                              'data, because there was no additional data specified.')

    def testAdditionalData(self):
        """ Test if the token storage can correctly store additional data for a token. """
        token = 'dataTestToken'
        tokenData = 'Some arbitrary data'
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE,
                                  additionalData=tokenData)
        self.assertEquals(tokenData, self._TOKEN_STORAGE.getTokenData(token)[1],
                          msg='Expected the token storage return the additional data '
                              'that was stored with the token.')

    def testExpireTime(self):
        """ Test that the token storage correctly expires the tokens. """
        expireTokens = ['expireToken1', 'expireToken2', 'expireToken3']
        noExpireToken = 'noExpireToken'
        futureExpireToken = 'futureExpireToken'
        hasExpiredToken = 'hasExpiredToken'
        for token in expireTokens:
            self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE,
                                      expireTime=time.time() + 1)
        self._TOKEN_STORAGE.store(noExpireToken, self._DUMMY_CLIENT, self._VALID_SCOPE)
        self._TOKEN_STORAGE.store(futureExpireToken, self._DUMMY_CLIENT, self._VALID_SCOPE,
                                  expireTime=time.time() + 600)
        self._TOKEN_STORAGE.store(hasExpiredToken, self._DUMMY_CLIENT, self._VALID_SCOPE,
                                  expireTime=time.time() - 10)
        for token in expireTokens:
            self.assertTrue(self._TOKEN_STORAGE.contains(token),
                            msg='Expected the token storage to contain the tokens '
                                'that will expire in a few seconds but have not yet.')
        self.assertTrue(
            self._TOKEN_STORAGE.contains(noExpireToken),
            msg='Expected the token storage to contain the token that will never expire.')
        self.assertTrue(self._TOKEN_STORAGE.contains(futureExpireToken),
                        msg='Expected the token storage to contain the token has not expired.')
        self.assertFalse(
            self._TOKEN_STORAGE.contains(hasExpiredToken),
            msg='Expected the token storage to not contain the token that has expired.')
        time.sleep(1.5)
        self.assertFalse(self._TOKEN_STORAGE.contains(expireTokens[0]),
                         msg='Expected the token storage to not contain an expired token.')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.hasAccess,
                          expireTokens[1], self._VALID_SCOPE)
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenData, expireTokens[2])
        self.assertTrue(
            self._TOKEN_STORAGE.contains(noExpireToken),
            msg='Expected the token storage to contain the token that will never expire.')
        self.assertTrue(self._TOKEN_STORAGE.contains(futureExpireToken),
                        msg='Expected the token storage to contain the token has not expired.')


class DictTokenStorageTest(AbstractTokenStorageTest):
    """ Test the DictTokenStorage. """

    @classmethod
    def setUpClass(cls):
        cls.setupTokenStorage(DictTokenStorage())
