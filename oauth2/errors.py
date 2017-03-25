# Copyright (c) Sebastian Scholz
# See LICENSE for details.

import json
from httplib import BAD_REQUEST, UNAUTHORIZED, OK
from urllib import urlencode

import logging
from twisted.web.server import NOT_DONE_YET


class OAuth2Error(object):
    message = None
    detail = None
    errorUri = None
    code = BAD_REQUEST
    logger = logging.getLogger('oauth2')

    def __init__(self, code, message, detail, errorUri=None):
        self.code = code
        self.message = message
        self.detail = detail
        self.errorUri = errorUri

    def _generateErrorBody(self):
        error = {"error": self.message}
        if self.detail is not None:
            error["error_description"] = self.detail
        if self.errorUri is not None:
            error["error_uri"] = self.errorUri
        return error

    def generate(self, request):
        request.setResponseCode(self.code)
        request.setHeader("Content-Type", "application/json;charset=UTF-8")
        request.setHeader("Cache-Control", "no-store")
        request.setHeader("Pragma", "no-cache")
        result = json.dumps(self._generateErrorBody()).encode("utf-8")
        self.logger.debug('OAuth2 Error: {result}'.format(result=result))
        return result


class AuthorizationError(OAuth2Error):
    state = None

    def __init__(self, code, message, detail, errorUri=None, state=None):
        super(AuthorizationError, self).__init__(code, message, detail, errorUri)
        self.state = state

    def _generateErrorBody(self):
        error = super(AuthorizationError, self)._generateErrorBody()
        if self.state is not None:
            error['state'] = self.state
        return error

    def generate(self, request, redirectUri=None):
        if redirectUri is None:
            return super(AuthorizationError, self).generate(request)
        else:
            request.setResponseCode(self.code)
            queryParameter = urlencode(self._generateErrorBody())
            request.redirect(redirectUri + '?' + queryParameter)
            request.finish()
            return NOT_DONE_YET


class MissingParameterError(AuthorizationError):
    def __init__(self, name=None, state=None):
        if name is None:
            message = "A required parameter was missing from the request."
        else:
            message = "Request was missing the '{name}' parameter.".format(name=name)
        super(MissingParameterError, self).__init__(BAD_REQUEST, "invalid_request",
                                                    message, state=state)


class InvalidParameterError(AuthorizationError):
    def __init__(self, name=None, state=None):
        if name is None:
            message = "A required parameter was invalid."
        else:
            message = "The parameter '{name}' is invalid.".format(name=name)
        super(InvalidParameterError, self).__init__(BAD_REQUEST, "invalid_request",
                                                    message, state=state)


class InsecureConnectionError(AuthorizationError):
    def __init__(self, state=None):
        message = "OAuth 2.0 requires calls over HTTPS."
        super(InsecureConnectionError, self).__init__(BAD_REQUEST, "invalid_request",
                                                      message, state=state)


class InvalidRedirectUriError(OAuth2Error):
    def __init__(self):
        message = "Invalid redirection URI."
        super(InvalidRedirectUriError, self).__init__(BAD_REQUEST, "invalid_request", message)


class InvalidClientIdError(OAuth2Error):
    def __init__(self):
        message = "Invalid client_id"
        super(InvalidClientIdError, self).__init__(UNAUTHORIZED, "invalid_client", message)


class InvalidTokenError(OAuth2Error):
    def __init__(self, tokenType):
        # tokenType: ["authorization code", "refresh token", "auth token", "credentials"]
        message = "The provided {type} is invalid".format(type=tokenType)
        super(InvalidTokenError, self).__init__(BAD_REQUEST, "invalid_grant", message)


class InvalidScopeError(OAuth2Error):
    def __init__(self, scope):
        message = "The provided scope is invalid: {scope}".format(scope=scope)
        super(InvalidScopeError, self).__init__(BAD_REQUEST, "invalid_scope", message)


class UserDeniesAuthorization(AuthorizationError):
    def __init__(self, state=None):
        super(UserDeniesAuthorization, self).__init__(OK, "access_denied", None, state=state)
