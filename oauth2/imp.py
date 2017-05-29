# Copyright (c) Sebastian Scholz
# See LICENSE for details.

from uuid import uuid4
import os
from ConfigParser import RawConfigParser, DuplicateSectionError

from oauth2.clients import ClientStorage, Client
from oauth2.token import TokenFactory


class UUIDTokenFactory(TokenFactory):
    def generateToken(self, client, scope, additionalData=None):
        return str(uuid4())


class SimpleClientStorage(ClientStorage):
    _configParser = None
    path = None

    def __init__(self, path):
        self._configParser = RawConfigParser()
        self.path = path
        self._configParser.read(path)

    def getClient(self, clientId):
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
        if not all(uri.startswith('https') for uri in client.redirectUris):
            raise ValueError("All redirectUris must be https")
        sectionName = 'client_' + client.clientId
        try:
            self._configParser.add_section(sectionName)
        except DuplicateSectionError:
            pass
        self._configParser.set(sectionName, 'name', client.name)
        self._configParser.set(sectionName, 'secret', client.clientSecret)
        self._configParser.set(sectionName, 'redirect_uris', ' '.join(client.redirectUris))
        if not os.path.exists(os.path.dirname(self.path)):
            os.makedirs(os.path.dirname(self.path))
        with open(self.path, 'w') as configFile:
            self._configParser.write(configFile)
