# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" Provides methods to authorize requests. """

from functools import wraps
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse, parse_qs

from twisted.web.server import NOT_DONE_YET

from txoauth2.errors import MissingTokenError, InvalidTokenRequestError, InsecureConnectionError, \
    InsufficientScopeRequestError, MultipleTokensError
from txoauth2.token import TokenResource


def _getToken(request):
    """
    Helper method to get a token from a request, if it contains any.
    :raises ValueError: If more than one token was found in the request.
    :param request: The request.
    :return: A token that was send with the request or None.
    """
    token = None
    authHeader = request.getHeader(b'Authorization')
    if authHeader is not None and authHeader.startswith(b'Bearer '):
        token = authHeader[7:]
    if b'access_token' in request.args:
        if request.method == b'POST' and\
                request.getHeader(b'Content-Type') == b'application/x-www-form-urlencoded':
            accessTokenArg = request.args[b'access_token']
        else:
            query = parse_qs(urlparse(request.uri).query)
            accessTokenArg = query.get(b'access_token')
            if accessTokenArg is not None:
                request.setHeader(b'Cache-Control', b'private')
        if accessTokenArg is not None:
            if token is not None or len(accessTokenArg) != 1:
                raise ValueError('Found multiple tokens in the request')
            token = accessTokenArg[0]
    return token


# pylint: disable=too-many-nested-blocks
def isAuthorized(request, scope, allowInsecureRequestDebug=False):
    """
    Returns True if the token in the request grants access to the given
    scope. The token is validated via the authTokenStorage singleton
    given to the TokenResource instance. If the token is invalid,
    does not grant access to the scope or was not send via a secure
    protocol, False is returned, an error is written to the request
    and the request is closed.
    You can not write to the request if this function returned False!
    :param request: The request.
    :param scope: The scope or list of scopes the token must grant access to.
    :param allowInsecureRequestDebug: Allow requests to originate from
           insecure connections. Only use for local testing!
    :return: True, if the request is authorized, False otherwise.
    """
    error = None
    scope = scope if isinstance(scope, list) else [scope]
    if not (allowInsecureRequestDebug or request.isSecure()):
        error = InsecureConnectionError()
    else:
        try:
            requestToken = _getToken(request)
        except ValueError:
            error = MultipleTokensError(scope)
        else:
            if requestToken is None:
                error = MissingTokenError(scope)
            else:
                try:
                    requestToken = requestToken.decode('utf-8')
                except UnicodeDecodeError:
                    pass
                else:
                    tokenStorage = TokenResource.getTokenStorageSingleton()
                    if tokenStorage.contains(requestToken):
                        if tokenStorage.hasAccess(requestToken, scope):
                            return True
                        error = InsufficientScopeRequestError(scope)
            if error is None:
                error = InvalidTokenRequestError(scope)
    request.write(error.generate(request))
    request.finish()
    return False


def oauth2(scope, allowInsecureRequestDebug=False):
    """
    Function decorator that checks the first argument, which must
    be a request object, with isAuthorized.
    If the request is authorized, the function is called,
    otherwise the request is closed and NOT_DONE_YET is returned.
    :param scope: The scope or list of scopes the token must grant access to.
    :param allowInsecureRequestDebug: Allow requests to originate from
           insecure connections. Only use for local testing!
    :return: The wrapped function.
    """
    def decorator(func):  # pylint: disable=missing-docstring
        @wraps(func)
        def wrapper(self, request, *args, **kwargs):  # pylint: disable=missing-docstring
            if not isAuthorized(request, scope, allowInsecureRequestDebug):
                return NOT_DONE_YET
            return func(self, request, *args, **kwargs)
        return wrapper
    return decorator
