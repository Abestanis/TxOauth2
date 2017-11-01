# Copyright (c) Sebastian Scholz
# See LICENSE for details.
from functools import wraps
from twisted.web.server import NOT_DONE_YET

from oauth2.errors import InvalidTokenError
from oauth2.resource import OAuth2
from oauth2.token import TokenResource


def _getToken(request):
    """
    Helper method to get a token from a request, if it contains any.
    :param request: The request.
    :return: A token that was send with the request or None.
    """
    return request.getHeader('Authorization')


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
    if allowInsecureRequestDebug or request.isSecure():
        tokenStr = _getToken(request)
        if tokenStr is not None and tokenStr.startswith('Bearer '):
            tokenStr = tokenStr[7:]
            scope = scope if type(scope) == list else [scope]
            if TokenResource.getTokenStorageSingleton().contains(tokenStr, scope):
                return True
    request.write(InvalidTokenError('auth token').generate(request))
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
    def decorator(func):
        def wrapper(self, request, *args, **kwargs):
            if not isAuthorized(request, scope, allowInsecureRequestDebug):
                return NOT_DONE_YET
            return func(self, request, *args, **kwargs)
        return wraps(func)(wrapper)
    return decorator
