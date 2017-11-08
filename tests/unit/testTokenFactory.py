from txoauth2.token import TokenResource

from txoauth2.imp import UUIDTokenFactory

from tests import TwistedTestCase, getDummyClient


class AbstractTokenFactoryTest(TwistedTestCase):
    """
    An abstract test case for TokenFactory implementations. A subclass must set __test__
    to True and call setupTokenFactory with an instance of the token factory to test.
    """
    _TOKEN_FACTORY = None
    _VALID_SCOPE = ['All', 'Scope1']
    _VALID_ADDITIONAL_DATA = 'additionalData'
    _DUMMY_CLIENT = getDummyClient()

    @classmethod
    def setupTokenFactory(cls, tokenFactory, client=_DUMMY_CLIENT):
        """
        Set the token factory implementation to use for the tests.
        :param tokenFactory: The token factory implementation to test.
        :param client: The client to use for token generation.
        """
        cls._TOKEN_FACTORY = tokenFactory
        cls._DUMMY_CLIENT = client

    def testTokenGeneration(self):
        """ Verify that the token factory generates valid tokens. """
        token = self._TOKEN_FACTORY.generateToken(None, self._DUMMY_CLIENT, self._VALID_SCOPE)
        self.assertIsInstance(token, str, message='Expected the token factory to return a string.')
        self.assertTrue(
            TokenResource.isValidToken(token),
            msg='The generated token is not valid according to the oauth2 specifications.')

    def testTokenUniqueness(self):
        """ Test that the token factory generates unique tokens. """
        tokens = [
            self._TOKEN_FACTORY.generateToken(None, self._DUMMY_CLIENT, self._VALID_SCOPE),
            self._TOKEN_FACTORY.generateToken(None, self._DUMMY_CLIENT, self._VALID_SCOPE),
            self._TOKEN_FACTORY.generateToken(200, self._DUMMY_CLIENT, self._VALID_SCOPE),
            self._TOKEN_FACTORY.generateToken(200, self._DUMMY_CLIENT, self._VALID_SCOPE),
        ]
        for firstToken in tokens:
            for secondToken in tokens:
                if firstToken is secondToken:
                    continue
                self.assertNotEqual(firstToken, secondToken,
                                    msg='Expected the token factory to generate unique tokens.')


class UUIDTokenFactoryTest(AbstractTokenFactoryTest):
    """ Test the UUIDTokenFactory. """

    @classmethod
    def setUpClass(cls):
        cls.setupTokenFactory(UUIDTokenFactory())
