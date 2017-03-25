# Copyright (c) Sebastian Scholz
# See LICENSE for details.
from functools import wraps
from twisted.web.server import NOT_DONE_YET

from oauth2.errors import InvalidTokenError
from oauth2.resource import OAuth2


def _getToken(request):
    return request.getHeader('Authorization')


def isAuthorized(request, scope, allowInsecureRequestDebug=False):
    if allowInsecureRequestDebug or request.isSecure():
        token = _getToken(request)
        if token is not None and token.startswith("Bearer "):
            token = token[7:]
            if OAuth2.OAuthTokenStorage.contains(token, scope):
                return True
    request.write(InvalidTokenError("auth token").generate(request))
    request.finish()
    return False


def oauth2(scope, allowInsecureRequestDebug=False):
    def decorator(func):
        def wrapper(self, request):
            if not isAuthorized(request, scope, allowInsecureRequestDebug):
                return NOT_DONE_YET
            return func(self, request)
        return wraps(func)(wrapper)
    return decorator
