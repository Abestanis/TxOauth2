from txoauth2.clients import Client, PasswordClient

from tests import TwistedTestCase
from txoauth2.util import isAnyStr


class ClientTest(TwistedTestCase):
    """ Tests the functionality of the Client object. """

    def testClientAttributeTypes(self):
        """ Ensure that all attributes of the client are of the expected type. """
        client = PasswordClient('clientId', ['https://valid.nonexistent'], ['password'], 'secret')
        self.assertTrue(isAnyStr(client.id), msg='The client id must be a string.')
        self.assertIsInstance(client.secret, str, message='The client secret must be a string.')
        self.assertIsInstance(client.redirectUris, list,
                              message='The redirect uris must be a list.')
        for uri in client.redirectUris:
            self.assertIsInstance(uri, str, message='All redirect uris must be strings.')
        self.assertIsInstance(client.authorizedGrantTypes, list,
                              message='The authorized grant types must be a list.')
        for grantType in client.authorizedGrantTypes:
            self.assertIsInstance(grantType, str, message='All grant types must be strings.')
        client = PasswordClient(u'clientId', ['https://valid.nonexistent'], ['password'], 'secret')
        self.assertTrue(isAnyStr(client.id), msg='The client id must be a string.')

    def testAcceptsValidUri(self):
        """ Check that the client does not reject valid redirect uris. """
        validUris = [
            'https://valid.nonexistent',
            'http://valid.nonexistent',
            'https://valid.nonexistent/path/subpath',
            'https://valid.nonexistent/path/subpath?querry=1',
        ]
        for uri in validUris:
            self.assertEquals(uri, Client('clientId', [uri], []).redirectUris[0],
                              msg='Expected the client to accept the valid redirect uri ' + uri)

    def testRejectsRedirectUrisWithFragment(self):
        """ Test that the Client rejects redirect uris with fragments. """
        self.assertRaises(ValueError, Client, 'clientId',
                          ['https://example.nonexistent/test#fragment'], [])
        self.assertRaises(ValueError, Client, 'clientId',
                          ['https://v.nonexistent', 'https://sth.nonexistent/test#fragment'], [])

    def testRejectsRelativeRedirectUris(self):
        """ Test that the client rejects relative redirect uris. """
        self.assertRaises(ValueError, Client, 'clientId', ['/relative'], [])
        self.assertRaises(ValueError, Client, 'clientId',
                          ['https://valid.nonexistent', '/test?q=1'], [])
