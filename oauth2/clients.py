# Copyright (c) Sebastian Scholz
# See LICENSE for details.


class ClientStorage(object):
    """
    This class's purpose is to manage and give access
    to the clients that the server knows via their clientId.
    """
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

    A client is an entity, which is given access to a scope
    by the user. He proves his identity and his rights by
    sending a key with every request, the token.
    """
    clientId = None
    clientSecret = None
    redirectUris = None
    """
    A list of urls, which we can redirect to after
    authorization. These are provided by the client.
    """
    name = None
    """
    A human readable name that identifies the client.
    The user must be absolutely clear who he is giving access to a scope.
    """
