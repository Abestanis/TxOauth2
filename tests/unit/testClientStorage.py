""" Client storage tests. """

import os
import shutil

from tempfile import NamedTemporaryFile, mkdtemp

from txoauth2 import GrantTypes
from txoauth2.clients import Client, PublicClient, PasswordClient
from txoauth2.imp import ConfigParserClientStorage

from tests import TwistedTestCase, getTestPasswordClient, assertClientEquals


class Abstract:
    """ Wrapper for the abstract ClientStorageTest to hide it during test discovery. """

    class ClientStorageTest(TwistedTestCase):
        """
        An abstract test case for ClientStorage implementations. A subclass must
        call setupClientStorage with an instance of the client storage to test.
        """
        _CLIENT_STORAGE = None
        _VALID_CLIENTS = [getTestPasswordClient(),
                          PublicClient('publicClient', ['https://return.nonexistent'], [])]

        @classmethod
        def setupClientStorage(cls, clientStorage):
            """
            Set the client storage implementation to use for the tests.
            The client storage must contain all _VALID_CLIENTS.
            :param clientStorage: The client storage implementation to test.
            """
            cls._CLIENT_STORAGE = clientStorage

        def testGetClient(self):
            """ Test the retrieval of clients from the client storage. """
            for validClient in self._VALID_CLIENTS:
                client = self._CLIENT_STORAGE.getClient(validClient.id)
                self.assertIsInstance(
                    client, Client,
                    message='Expected the client storage to return a client object.')
                self.assertIsInstance(client, validClient.__class__,
                                      message='Expected the client storage to return a client '
                                              'object of the same subclass as the original client.')
                self.assertIsInstance(client.id, str,
                                      message='Expected the client id of the client returned '
                                              'by the client storage to be a string.')
                self.assertIsInstance(client.redirectUris, list,
                                      message='Expected the redirect uris of the client returned '
                                              'by the client storage to be a list.')
                for uri in client.redirectUris:
                    self.assertIsInstance(uri, str,
                                          message='Expected all redirect uris of the client '
                                                  'returned by the client storage to be a string.')
                self.assertIsInstance(client.authorizedGrantTypes, list,
                                      message='Expected the authorized grant types of the client '
                                              'returned by the client storage to be a list.')
                for grantType in client.authorizedGrantTypes:
                    self.assertIsInstance(grantType, str,
                                          message='Expected all grant types of the client returned '
                                                  'by the client storage to be a string.')
                assertClientEquals(
                    self, client, validClient,
                    message='Expected the attributes of the client returned by the client storage '
                            'to have the same values as the attributes of the original client.')

        def testGetNonExistentClient(self):
            """ Test handling of requests for clients that do net exist in the client storage. """
            self.assertRaises(KeyError, self._CLIENT_STORAGE.getClient, 'nonExistentClientId')


class ConfigParserClientStorageTest(Abstract.ClientStorageTest):
    """ Test the ConfigParserClientStorage. """
    NOT_FOUND_CLASS_CLIENT_ID = 'notFoundClassClientId'

    @classmethod
    def setUpClass(cls):
        with NamedTemporaryFile(prefix='.ini', delete=False) as tempFile:
            cls.clientStoragePath = tempFile.name
        clientStorage = ConfigParserClientStorage(cls.clientStoragePath)
        cls.setupClientStorage(clientStorage)
        for client in cls._VALID_CLIENTS:
            clientStorage.addClient(client)

        class TestNotFoundClassClient(PublicClient):
            """ A Client class that will not be found by getClient. """

            def __init__(self):
                super(TestNotFoundClassClient, self).__init__(
                    ConfigParserClientStorageTest.NOT_FOUND_CLASS_CLIENT_ID, [], [])

        clientStorage.addClient(TestNotFoundClassClient())

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.clientStoragePath)

    def testAddClient(self):
        """ Test if a client can be added to the client storage. """
        client = PublicClient(
            'newPublicClientId', ['https://return.nonexistent', 'https://return2.nonexistent'],
            [GrantTypes.REFRESH_TOKEN])
        self._CLIENT_STORAGE.addClient(client)
        self.assertListEqual(
            self._CLIENT_STORAGE.getClient(client.id).authorizedGrantTypes,
            client.authorizedGrantTypes,
            msg='Expected the client storage to contain a client after adding him.')
        client = PasswordClient(
            'newPasswordClientId', ['https://return.nonexistent', 'https://return2.nonexistent'],
            ['client_credentials'], 'newClientSecret')
        self._CLIENT_STORAGE.addClient(client)
        self.assertEqual(
            client.secret, self._CLIENT_STORAGE.getClient(client.id).secret,
            msg='Expected the client storage to contain a client after adding him.')

    def testGetUnknownClient(self):
        """ Test handling of requests for clients that do net exist in the client storage. """
        self.assertRaises(
            ValueError, self._CLIENT_STORAGE.getClient, self.NOT_FOUND_CLASS_CLIENT_ID)

    def testWritingInNonexistentDirectory(self):
        """ Test that the client storage is able to write to a location that doesn't exist. """
        tempDir = mkdtemp()
        try:
            clientStorage = ConfigParserClientStorage(
                os.path.join(tempDir, 'nonexistentDir', 'test.ini'))
            try:
                clientStorage.addClient(self._VALID_CLIENTS[0])
            except IOError as error:
                self.fail('Expected the ConfigParserClientStorage to write to a location that does '
                          'not exist, but got an error: {msg}'.format(msg=error))
        finally:
            shutil.rmtree(tempDir, ignore_errors=True)
