# Copyright (c) Sebastian Scholz
# See LICENSE for details.
from enum import Enum

__all__ = ['isAuthorized', 'oauth2', 'clients', 'errors', 'imp', 'resource', 'token', 'GrantTypes']


class GrantTypes(Enum):
    """ The different grant types to request a token defined by the OAuth2 spec. """
    RefreshToken = 'refresh_token'
    AuthorizationCode = 'authorization_code'
    ClientCredentials = 'client_credentials'
    Password = 'password'
    Implicit = 'implicit'


from .authorization import oauth2, isAuthorized
