""" Tests for a token storage. """

import time

from txoauth2.imp import DictTokenStorage

from tests import TwistedTestCase, getTestPasswordClient


class AbstractTokenStorageTest(TwistedTestCase):
    """
    An abstract test case for TokenStorage implementations. A subclass must set __test__
    to True and call setupTokenStorage with an instance of the token storage to test.
    """
    _TOKEN_STORAGE = None
    _VALID_TOKEN = 'ValidToken'
    _VALID_SCOPE = ['All', 'Scope1']
    _VALID_ADDITIONAL_DATA = 'additionalData'
    _DUMMY_CLIENT = getTestPasswordClient()

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
        self.assertTrue(self._TOKEN_STORAGE.hasAccess(self._VALID_TOKEN, self._VALID_SCOPE[0]),
                        msg='Expected hasAccess to return True '
                            'for a valid token and a single valid scope.')
        self.assertFalse(self._TOKEN_STORAGE.hasAccess(self._VALID_TOKEN, 'invalidScope'),
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

    def testTokenClient(self):
        """ Test that the token storage returns the correct client id for a token. """
        self.assertEqual(
            self._DUMMY_CLIENT.id, self._TOKEN_STORAGE.getTokenClient(self._VALID_TOKEN),
            msg='Expected getTokenClient to return the correct client id for the token.')
        token = 'otherValidToken'
        client = getTestPasswordClient('otherClientId')
        self._TOKEN_STORAGE.store(token, client, self._VALID_SCOPE)
        self.assertEqual(client.id, self._TOKEN_STORAGE.getTokenClient(token),
                         msg='Expected getTokenClient to return the client id given to store.')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenClient, 'invalidToken')

    def testTokenScope(self):
        """ Test that the token storage returns the correct scope for a token. """
        self.assertListEqual(
            self._VALID_SCOPE, self._TOKEN_STORAGE.getTokenScope(self._VALID_TOKEN),
            msg='Expected getTokenScope to return the correct scope for the token.')
        token = 'otherValidToken'
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE[0:1])
        self.assertListEqual(self._VALID_SCOPE[0:1], self._TOKEN_STORAGE.getTokenScope(token),
                             msg='Expected getTokenScope to return the scope given to store.')
        token = 'differentValidToken'
        scope = self._VALID_SCOPE[0]
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, scope)
        self.assertListEqual(
            [scope], self._TOKEN_STORAGE.getTokenScope(token),
            msg='Expected the token storage return the scope as a list '
                'even if it was passed as a single string to store.')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenScope, 'invalidToken')

    def testAdditionalData(self):
        """ Test if the token storage can correctly store additional data for a token. """
        self.assertEqual(self._VALID_ADDITIONAL_DATA,
                         self._TOKEN_STORAGE.getTokenAdditionalData(self._VALID_TOKEN),
                         msg='Expected getTokenAdditionalData to return '
                             'the correct additional data for the token.')
        token = 'dataTestToken'
        tokenData = 'Some arbitrary data'
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE,
                                  additionalData=tokenData)
        self.assertEqual(tokenData, self._TOKEN_STORAGE.getTokenAdditionalData(token),
                         msg='Expected the token storage return the additional data '
                             'that was stored with the token.')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenAdditionalData, 'invalidToken')

    def testGetTokenLifetime(self):
        """ Test that the token storage correctly reports the lifetime of a token """
        token = 'lifetimeToken'
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE[0:1])
        self.assertEqual(
            0, self._TOKEN_STORAGE.getTokenLifetime(token),
            msg='Expected the token resource to return the correct lifetime of the token.')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenLifetime, 'nonExistentToken')

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
                        msg='Expected the token storage to indicate that the token '
                            'has access to the scopes it was created with.')
        self.assertListEqual(
            self._VALID_SCOPE, self._TOKEN_STORAGE.getTokenScope(token),
            msg='Expected the token storage return the same scope that was supplied to store.')
        self.assertIsNone(self._TOKEN_STORAGE.getTokenAdditionalData(token),
                          msg='Expected the token storage return None as the additional data '
                              'for a token if none was supplied to store.')
        self.assertRaises(ValueError, self._TOKEN_STORAGE.store,
                          None, self._DUMMY_CLIENT, self._VALID_SCOPE)
        self.assertRaises(ValueError, self._TOKEN_STORAGE.store,
                          42, self._DUMMY_CLIENT, self._VALID_SCOPE)

    def testRemove(self):
        """ Test that the token storage correctly removes tokens. """
        token = 'removeToken'
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE)
        self.assertTrue(self._TOKEN_STORAGE.contains(token),
                        msg='Expected the token storage to contain the token after it was stored.')
        self._TOKEN_STORAGE.remove(token)
        self.assertFalse(
            self._TOKEN_STORAGE.contains(token),
            msg='Expected the token storage to not contain the token after it has been removed.')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.remove, 'nonExistentToken')

    def testTokenOverwrite(self):
        """
        Test that the token storage correctly overwrites an existing token.
        Note that this should not happen if the TokenFactory is implemented correctly.
        """
        token = 'overwriteTestToken'
        tokenData = 'token data'
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE)
        self.assertListEqual(
            self._VALID_SCOPE, self._TOKEN_STORAGE.getTokenScope(token),
            msg='Expected getTokenScope to return the scope that was stored with the token.')
        self.assertIsNone(self._TOKEN_STORAGE.getTokenAdditionalData(token),
                          msg='Expected getTokenScope to return the additional '
                              'data that was stored with the token.')
        self.assertEqual(
            self._DUMMY_CLIENT.id, self._TOKEN_STORAGE.getTokenClient(token),
            msg='Expected getTokenScope to return the client id that was stored with the token.')
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE[0:1],
                                  additionalData=tokenData)
        self.assertListEqual(
            self._VALID_SCOPE[0:1], self._TOKEN_STORAGE.getTokenScope(token),
            msg='Expected getTokenScope to return the new scope that was stored with the token.')
        self.assertEqual(tokenData, self._TOKEN_STORAGE.getTokenAdditionalData(token),
                         msg='Expected getTokenScope to return the new additional '
                             'data that was stored with the token.')
        self.assertEqual(
            self._DUMMY_CLIENT.id, self._TOKEN_STORAGE.getTokenClient(token),
            msg='Expected getTokenScope to return the new client id that was stored with the token.'
        )
        self._TOKEN_STORAGE.store(token, self._DUMMY_CLIENT, self._VALID_SCOPE[1:2])
        self.assertListEqual(
            self._VALID_SCOPE[1:2], self._TOKEN_STORAGE.getTokenScope(token),
            msg='Expected getTokenScope to return the new scope that was stored with the token.')
        self.assertIsNone(self._TOKEN_STORAGE.getTokenAdditionalData(token),
                          msg='Expected getTokenScope to return the new additional '
                              'data that was stored with the token.')
        self.assertEqual(
            self._DUMMY_CLIENT.id, self._TOKEN_STORAGE.getTokenClient(token),
            msg='Expected getTokenScope to return the new client id that was stored with the token.'
        )

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
                        msg='Expected the token storage to contain the token that has not expired.')
        self.assertFalse(
            self._TOKEN_STORAGE.contains(hasExpiredToken),
            msg='Expected the token storage to not contain the token that has expired.')
        time.sleep(1.5)
        self.assertFalse(self._TOKEN_STORAGE.contains(expireTokens[0]),
                         msg='Expected the token storage to not contain an expired token.')
        self.assertRaises(KeyError, self._TOKEN_STORAGE.hasAccess,
                          expireTokens[1], self._VALID_SCOPE)
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenAdditionalData, expireTokens[2])
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenClient, expireTokens[2])
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenScope, expireTokens[2])
        self.assertRaises(KeyError, self._TOKEN_STORAGE.getTokenLifetime, expireTokens[2])
        self.assertTrue(
            self._TOKEN_STORAGE.contains(noExpireToken),
            msg='Expected the token storage to contain the token that will never expire.')
        self.assertTrue(self._TOKEN_STORAGE.contains(futureExpireToken),
                        msg='Expected the token storage to contain the token has not expired.')
        self.assertGreaterEqual(
            self._TOKEN_STORAGE.getTokenLifetime(noExpireToken), 1,
            msg='Expected the token storage to correctly report the lifetime of the token.')


class DictTokenStorageTest(AbstractTokenStorageTest):
    """ Test the DictTokenStorage. """

    @classmethod
    def setUpClass(cls):
        cls.setupTokenStorage(DictTokenStorage())
