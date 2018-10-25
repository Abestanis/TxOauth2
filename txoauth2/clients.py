# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" Classes for representing and dealing with oauth2 clients """

from abc import abstractmethod, ABCMeta
try:
    from urlparse import urlparse
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse

from txoauth2.util import isAnyStr
from txoauth2.granttypes import GrantTypes
from txoauth2.errors import InvalidClientAuthenticationError, NoClientAuthenticationError


class ClientStorage(object):
    """
    This class's purpose is to manage and give access
    to the clients that the server knows via their clientId.
    """
    __metaclass__ = ABCMeta

    # noinspection PyMethodMayBeStatic
    # pylint: disable=no-self-use
    def authenticateClient(self, client, request, secret=None):
        """
        Authenticate a given client.
        :param client: The client that should get authenticated.
        :param request: The request that may contain the credentials for a client.
        :param secret: The client secret, if it could get extracted from the request.
        :return: The client that was authenticated by the request or an OAuth2Error.
        """
        del request  # Unused
        if secret is not None:
            if isinstance(client, PasswordClient) and client.secret == secret:
                return client
            return InvalidClientAuthenticationError()
        return NoClientAuthenticationError()

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

    A client is an entity, which is given access to a scope by the user.
    He can use a grant type he is authorized to use to request an access token
    with which he can access resources on behalf of the user.
    """

    def __init__(self, clientId, redirectUris, authorizedGrantTypes):
        """
        :raises ValueError: If one of the argument is not of the expected type
                            or one of the redirect uris has a fragment.
        :param clientId: The id of this client.
        :param redirectUris: A list of urls, which we can redirect to after authorization.
        :param authorizedGrantTypes: A list of grant types that this client is authorized
                                     to use to get an access token.
        """
        super(Client, self).__init__()
        if not isAnyStr(clientId):
            raise ValueError('Expected clientId must be a string, got ' + str(type(clientId)))
        if not isinstance(redirectUris, list):
            raise ValueError('Expected redirectUris to be of type list, got '
                             + str(type(redirectUris)))
        for uri in redirectUris:
            if not isinstance(uri, str):
                raise ValueError('Expected the redirectUris to be of type str, got '
                                 + str(type(uri)))
            parsedUri = urlparse(uri)
            if parsedUri.fragment != '':
                raise ValueError('Got a redirect uri with a fragment: ' + uri)
            if parsedUri.netloc == '':
                raise ValueError('Got a redirect uri that is not absolute: ' + uri)
        authorizedGrantTypes = [grantType.value if isinstance(grantType, GrantTypes) else grantType
                                for grantType in authorizedGrantTypes]
        if not isinstance(authorizedGrantTypes, list):
            raise ValueError('Expected authorizedGrantTypes to be of type list, got '
                             + str(type(authorizedGrantTypes)))
        for grantType in authorizedGrantTypes:
            if not isinstance(grantType, str):
                raise ValueError('Expected the grant types to be of type str, got '
                                 + str(type(grantType)))
        self.id = clientId  # pylint: disable=invalid-name
        self.redirectUris = redirectUris
        self.authorizedGrantTypes = authorizedGrantTypes


class PublicClient(Client):
    """
    This is a public client which is not able to maintain the confidentiality of their
    credentials and thus are not required to authenticate themselves.
    See: https://tools.ietf.org/html/rfc6749#section-2.1
    """
    def __init__(self, clientId, redirectUris, authorizedGrantTypes):
        super(PublicClient, self).__init__(clientId, redirectUris, authorizedGrantTypes)


class PasswordClient(Client):
    """
    This is a confidential client which authenticates himself with a password/secret.
    See: https://tools.ietf.org/html/rfc6749#section-2.3.1
    """
    def __init__(self, clientId, redirectUris, authorizedGrantTypes, secret):
        super(PasswordClient, self).__init__(clientId, redirectUris, authorizedGrantTypes)
        self.secret = secret
