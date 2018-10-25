# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" Implementations to some of the abstract classes used by this module. """

import os
import time

from uuid import uuid4
try:
    from ConfigParser import RawConfigParser
except ImportError:
    # noinspection PyUnresolvedReferences
    from configparser import RawConfigParser

from txoauth2.clients import ClientStorage, Client
from txoauth2.token import TokenFactory, TokenStorage, PersistentStorage


class UUIDTokenFactory(TokenFactory):
    """ A TokenFactory that generates UUID tokens. """
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


class ConfigParserClientStorage(ClientStorage):
    """ A ClientStorage using a ConfigParser. """
    _configParser = None
    path = None

    def __init__(self, path):
        """
        Initialize a new SimpleClientStorage which loads and stores
        it's clients from the given path.
        :param path: Path to a config file to load and store clients.
        """
        super(ConfigParserClientStorage, self).__init__()
        self._configParser = RawConfigParser()
        self.path = os.path.abspath(path)
        self._configParser.read(self.path)
        self._clientClasses = self._findClientClasses()

    def getClient(self, clientId):
        """
        Return a client object which represents the client
        with the given client id.
        :raises KeyError: If no client with the given client id exists.
        :param clientId: The id of the client.
        :return: A client object.
        """
        sectionName = 'client_' + clientId
        if not isinstance(sectionName, str):  # clientId is unicode
            sectionName = sectionName.encode('utf-8')
            clientId = clientId.encode('utf-8')
        if not self._configParser.has_section(sectionName):
            raise KeyError('No client with id "{id}" exists'.format(id=clientId))
        clientType = self._configParser.get(sectionName, 'type')
        for cls in self._clientClasses:
            if cls.__name__ == clientType:
                clientClass = cls
                break
        else:
            raise ValueError('Unable to find client class ' + clientType)
        redirectUris = self._configParser.get(sectionName, 'redirect_uris').split()
        authorizedGrantTypes = self._configParser.get(sectionName, 'authorized_grant_types').split()
        kwargs = {key: value for key, value in self._configParser.items(sectionName)
                  if key not in ['type', 'redirect_uris', 'authorized_grant_types']}
        return clientClass(clientId, redirectUris, authorizedGrantTypes, **kwargs)

    def addClient(self, client):
        """
        Add a new or update an existing client to the list
        and save it to the config file.
        :raises ValueError: If the data in the client is not valid.
        :param client: The client to update or add.
        """
        sectionName = 'client_' + client.id
        if not self._configParser.has_section(sectionName):
            self._configParser.add_section(sectionName)
        self._configParser.set(sectionName, 'type', client.__class__.__name__)
        self._configParser.set(sectionName, 'redirect_uris', ' '.join(client.redirectUris))
        self._configParser.set(sectionName, 'authorized_grant_types',
                               ' '.join(client.authorizedGrantTypes))
        for name, value in client.__dict__.items():
            if name not in ['id', 'redirectUris', 'authorizedGrantTypes']:
                self._configParser.set(sectionName, name, value)
        if not os.path.exists(os.path.dirname(self.path)):
            os.makedirs(os.path.dirname(self.path))
        with open(self.path, 'w') as configFile:
            self._configParser.write(configFile)

    @staticmethod
    def _findClientClasses():
        classes = set()
        newClasses = {Client}
        while len(newClasses) != 0:
            newClasses = {subclass for cls in newClasses for subclass in cls.__subclasses__()}
            newClasses -= classes
            classes |= newClasses
        return classes


class DictTokenStorage(TokenStorage):
    """
    This token storage does not implement any type of persistence and tokens will therefore
    not survive a server restart. This implementation should probably only be used for testing.
    """
    _tokens = {}

    def contains(self, token):
        if token not in self._tokens:
            return False
        return not self._checkExpire(token)

    def hasAccess(self, token, scope):
        if self._checkExpire(token):
            raise KeyError('Token expired')
        for scopeItem in scope:
            if scopeItem not in self._tokens[token]['scope']:
                return False
        return True

    def getTokenAdditionalData(self, token):
        self._checkExpire(token)
        return self._tokens[token]['data']

    def getTokenScope(self, token):
        self._checkExpire(token)
        return self._tokens[token]['scope']

    def getTokenClient(self, token):
        self._checkExpire(token)
        return self._tokens[token]['client']

    def getTokenLifetime(self, token):
        self._checkExpire(token)
        return int(time.time()) - self._tokens[token]['birthTime']

    def store(self, token, client, scope, additionalData=None, expireTime=None):
        if not isinstance(token, str):
            raise ValueError('Token parameter is not a string')
        if not isinstance(scope, list):
            scope = [scope]
        if expireTime is not None and expireTime <= time.time():
            return
        self._tokens[token] = {
            'data': additionalData,
            'birthTime': int(time.time()),
            'expireTime': expireTime,
            'scope': scope,
            'client': client.id
        }

    def remove(self, token):
        del self._tokens[token]

    def _checkExpire(self, token):
        """
        Check if a token has expired and remove it if necessary.
        :raises KeyError: If the token is not in the token storage.
        :param token: The token to check.
        :return: True if the token has expired.
        """
        expireTime = self._tokens[token]['expireTime']
        if expireTime is not None and time.time() > expireTime:
            del self._tokens[token]
            return True
        return False


class DictNonPersistentStorage(PersistentStorage):
    """
    This storage implementation does not implement any type of persistence.
    It is intended to be used when persistence is not really important.
    If you can live with the fact that the user might have to authorize a client again
    if the server restarted at an unlucky time, than you can use this
    as a pseudo persistence storage.
    """
    storage = {}

    def put(self, key, data, expireTime=None):
        self.storage[key] = {
            'data': data,
            'expires': expireTime
        }

    def pop(self, key):
        entry = self.storage.pop(key)
        if entry['expires'] is not None and time.time() > entry['expires']:
            raise KeyError(key)
        return entry['data']
