# Copyright (c) Sebastian Scholz
# See LICENSE for details.

import os

from uuid import uuid4
try:
    from ConfigParser import RawConfigParser
except ImportError:
    from configparser import RawConfigParser

from oauth2.clients import ClientStorage, Client
from oauth2.token import TokenFactory


class UUIDTokenFactory(TokenFactory):
    """
    A TokenFactory that generates UUID tokens.
    """
    def generateToken(self, lifetime, client, scope, additionalData=None):
        """
        Generate an UUID toke.
        :param lifetime: Unused.
        :param client: Unused.
        :param scope: Unused.
        :param additionalData: Unused.
        :return: An UUID token.
        """
        return str(uuid4())


class SimpleClientStorage(ClientStorage):
    """
    A ClientStorage using a ConfigParser.
    """
    _configParser = None
    path = None

    def __init__(self, path):
        """
        Initialize a new SimpleClientStorage which loads and stores
        it's clients from the given path.
        :param path: Path to a config file to load and store clients.
        """
        self._configParser = RawConfigParser()
        self.path = path
        self._configParser.read(path)

    def getClient(self, clientId):
        """
        Return a client object which represents the client
        with the given client id.
        :raises KeyError: If no client with the given client id exists.
        :param clientId: The id of the client.
        :return: A client object.
        """
        sectionName = 'client_' + clientId
        if not self._configParser.has_section(sectionName):
            raise KeyError('No client with id "{id}" exists'.format(id=clientId))
        client = Client()
        client.clientId = clientId
        client.name = self._configParser.get(sectionName, 'name')
        client.clientSecret = self._configParser.get(sectionName, 'secret')
        client.redirectUris = self._configParser.get(sectionName, 'redirect_uris').split()
        return client

    def addClient(self, client):
        """
        Add a new or update an existing client to the list
        and save it to the config file.
        :raises ValueError: If the data in the client is not valid.
        :param client: The client to update or add.
        """
        if not all(uri.startswith('https') for uri in client.redirectUris):
            raise ValueError("All redirectUris must be https")
        sectionName = 'client_' + client.clientId
        if not self._configParser.has_section(sectionName):
            self._configParser.add_section(sectionName)
        self._configParser.set(sectionName, 'name', client.name)
        self._configParser.set(sectionName, 'secret', client.clientSecret)
        self._configParser.set(sectionName, 'redirect_uris', ' '.join(client.redirectUris))
        if not os.path.exists(os.path.dirname(self.path)):
            os.makedirs(os.path.dirname(self.path))
        with open(self.path, 'w') as configFile:
            self._configParser.write(configFile)
