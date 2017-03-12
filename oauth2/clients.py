# Copyright (c) Sebastian Scholz
# See LICENSE for details.


class ClientStorage(object):
    def getClient(self, clientId):
        # Raise KeyError if no client with id clientId exists
        raise NotImplementedError()


class Client(object):
    clientId = None
    redirectUris = None
    name = None
