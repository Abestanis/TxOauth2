# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" All the grant types that we support """

from enum import Enum


class GrantTypes(Enum):
    """ The different grant types to request a token defined by the OAuth2 spec. """
    RefreshToken = 'refresh_token'
    AuthorizationCode = 'authorization_code'
    ClientCredentials = 'client_credentials'
    Password = 'password'
    Implicit = 'implicit'
