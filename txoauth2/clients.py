# Copyright (c) Sebastian Scholz
# See LICENSE for details.
from abc import abstractmethod, ABCMeta
try:
    from urlparse import urlparse
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse

from enum import Enum


class ClientAuthType(Enum):
    """ Indicate the type of authentication used to authenticate a client. """
    PUBLIC = -1
    PASSWORD = 0
    SECRET = 1
    CUSTOM = 2


class ClientStorage(object):
    """
    This class's purpose is to manage and give access
    to the clients that the server knows via their clientId.
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def getClient(self, clientId):
        """
        Return a Client object representing the client with
        the given clientId.
        :raises KeyError: If no client with the given clientId is found.
        :param clientId: The client id of the client.
        :return: The Client object.
        """
        raise NotImplementedError()


class Client(object):
    """
    This class represents a client.

    A client is an entity, which is given access to a scope by the user. He proves
    his right to access a resource by sending an authentication token with every request.
    He identifies himself with the clientId and the authToken, which is specific to the authType.
    """

    def __init__(self, clientId, redirectUris, authType=ClientAuthType.PUBLIC, authToken=None):
        """
        :raises ValueError: If one of the argument is not of the expected type
                            or one of the redirect uris has a fragment.
        :param clientId: The id of this client.
        :param redirectUris: A list of urls, which we can redirect to after authorization.
        :param authType: The type of authentication used to authenticate the client
                         or PUBLIC if the client is a public client.
        :param authToken: The token specific to the authentication type.
        """
        super(Client, self).__init__()
        if not isinstance(clientId, str):
            raise ValueError('Expected clientId to be of type str, got ' + str(type(clientId)))
        if not isinstance(redirectUris, list):
            raise ValueError('Expected redirectUris to be of type list, got '
                             + str(type(redirectUris)))
        if not all(isinstance(uri, str) for uri in redirectUris):
                raise ValueError('Expected the redirectUris to be of type str')
        for uri in redirectUris:
            if not isinstance(uri, str):
                raise ValueError('Expected the redirectUris to be of type str, got '
                                 + str(type(uri)))
            parsedUri = urlparse(uri)
            if parsedUri.fragment != '':
                raise ValueError('Got a redirect uri with a fragment: ' + uri)
            if parsedUri.netloc != '':
                raise ValueError('Got a redirect uri that is not absolute: ' + uri)
        if not isinstance(authType, ClientAuthType):
            raise ValueError('Expected authType to be of type ClientAuthType, got '
                             + str(type(authType)))
        if authType in [ClientAuthType.PASSWORD, ClientAuthType.SECRET] and\
                not isinstance(authToken, str):
            raise ValueError('Expected authToken to be of type str, got ' + str(type(authToken)))
        self.id = clientId
        self.redirectUris = redirectUris
        self.authType = authType
        self.authToken = authToken
