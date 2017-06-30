# Copyright (c) Sebastian Scholz
# See LICENSE for details.
from functools import wraps
from twisted.web.server import NOT_DONE_YET

from oauth2.errors import InvalidTokenError
from oauth2.resource import OAuth2
from oauth2.token import TokenResource


def _getToken(request):
    return request.getHeader('Authorization')


def isAuthorized(request, scope, allowInsecureRequestDebug=False):
    if allowInsecureRequestDebug or request.isSecure():
        tokenStr = _getToken(request)
        if tokenStr is not None and tokenStr.startswith("Bearer "):
            tokenStr = tokenStr[7:]
            scope = scope if type(scope) == list else [scope]
            if TokenResource.getTokenStorageSingleton().contains(tokenStr, scope):
                return True
    request.write(InvalidTokenError("auth token").generate(request))
    request.finish()
    return False


def oauth2(scope, allowInsecureRequestDebug=False):
    def decorator(func):
        def wrapper(self, request, *args, **kwargs):
            if not isAuthorized(request, scope, allowInsecureRequestDebug):
                return NOT_DONE_YET
            return func(self, request, *args, **kwargs)
        return wraps(func)(wrapper)
    return decorator
