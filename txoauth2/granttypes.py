# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" All the grant types that we support """

from enum import Enum


class GrantTypes(Enum):
    """ The different grant types to request a token defined by the OAuth2 spec. """
    REFRESH_TOKEN = 'refresh_token'
    AUTHORIZATION_CODE = 'authorization_code'
    CLIENT_CREDENTIALS = 'client_credentials'
    PASSWORD = 'password'
    IMPLICIT = 'implicit'
