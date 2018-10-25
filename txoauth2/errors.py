# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" All errors for the oauth2 flows. """

import json
import logging

from twisted.web.server import NOT_DONE_YET

from txoauth2.util import addToUrl

OK = 200
BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
INTERNAL_SERVER_ERROR = 500
SERVICE_UNAVAILABLE = 503


class OAuth2Error(object):
    """
    Represents an OAuth2 error. This is not a Python exception and cannot be raised.
    It is intended to return a json description of the error and setting the response
    code of the request via the generate method, to comply with the OAuth2 specification.
    """
    message = None
    detail = None
    errorUri = None
    code = BAD_REQUEST
    _logger = logging.getLogger('txOauth2')

    def __init__(self, code, message, detail, errorUri=None):
        self.code = code
        self.message = message
        self.detail = detail
        self.errorUri = errorUri

    def _generateErrorBody(self):
        error = {'error': self.message}
        if self.detail is not None:
            error['error_description'] = self.detail
        if self.errorUri is not None:
            error['error_uri'] = self.errorUri
        return error

    def generate(self, request):
        """
        Set the response code of the request and return a string representing
        the error, which can be written to the request.
        :param request: The request.
        :return: A string representing the error.
        """
        request.setResponseCode(self.code)
        request.setHeader('Content-Type', 'application/json;charset=UTF-8')
        request.setHeader('Cache-Control', 'no-store')
        request.setHeader('Pragma', 'no-cache')
        result = json.dumps(self._generateErrorBody()).encode('utf-8')
        self._logger.debug('OAuth2 error: %s', result)
        return result


class AuthorizationError(OAuth2Error):
    """
    Represents an error can occur during authorization. The OAuth2 specification says
    that these errors should be send to the redirection url with the error details
    encoded into the url parameters of the redirect.
    """
    state = None

    def __init__(self, code, message, detail, errorUri=None, state=None):
        super(AuthorizationError, self).__init__(code, message, detail, errorUri)
        self.state = state

    def _generateErrorBody(self):
        error = super(AuthorizationError, self)._generateErrorBody()
        if self.state is not None:
            error['state'] = self.state
        return error

    # pylint: disable=arguments-differ
    def generate(self, request, redirectUri=None, errorInFragment=False):
        """
        If a redirectUri is given, the request is redirected to the url with the error details
        encoded into the url parameter. Otherwise it behaves like generate in OAuth2Error.
        :param request: The request.
        :param redirectUri: An optional redirect uri.
        :param errorInFragment: Whether or not the error should be send in the query or fragment.
        :return: NOT_DONE_YET or a string representing the error.
        """
        if redirectUri is None:
            return super(AuthorizationError, self).generate(request)
        request.setResponseCode(self.code)
        errorParameter = self._generateErrorBody()
        self._logger.debug('OAuth2 error: %s', str(errorParameter))
        for key, value in errorParameter.items():
            if not isinstance(value, (bytes, str)):
                errorParameter[key] = value.encode('utf-8')  # For Python 2 unicode strings
        destination = 'fragment' if errorInFragment else 'query'
        request.redirect(addToUrl(redirectUri, **{destination: errorParameter}))
        request.finish()
        return NOT_DONE_YET


class OAuth2RequestError(OAuth2Error):
    """ An error that happens during a request to a protected resource. """
    _wwwAuthenticateContent = ''
    scope = []

    def __init__(self, code, message, detail, scope, errorUri=None, addDetailsToHeader=True):
        super(OAuth2RequestError, self).__init__(code, message, detail, errorUri)
        self.scope = scope
        if addDetailsToHeader:
            self._wwwAuthenticateContent += ',scope="' + ' '.join(scope) + '"'
            self._wwwAuthenticateContent += ',error="' + message + '"'
            self._wwwAuthenticateContent += ',error_description="' + detail + '"'
            if errorUri is not None:
                self._wwwAuthenticateContent += ',error_uri="' + errorUri + '"'

    def _generateErrorBody(self):
        body = super(OAuth2RequestError, self)._generateErrorBody()
        body['scope'] = self.scope[0] if len(self.scope) == 1 else self.scope
        return body

    def generate(self, request):
        content = 'Bearer realm="{realm}"'.format(realm=request.prePathURL())\
                  + self._wwwAuthenticateContent
        request.setHeader('WWW-Authenticate', content)
        return super(OAuth2RequestError, self).generate(request)


class UnauthorizedOAuth2Error(OAuth2Error):
    """ Error during a request to the token resource without valid client credentials. """

    def __init__(self, code, message, detail, errorUri=None):
        super(UnauthorizedOAuth2Error, self).__init__(code, message, detail, errorUri)

    def generate(self, request):
        authorizationHeader = request.getHeader(b'Authorization')
        if authorizationHeader is not None:
            authType = authorizationHeader.strip().split(b' ', 1)[0]
            request.setHeader(b'WWW-Authenticate',
                              authType + b' realm="' + request.prePathURL() + b'"')
        return super(UnauthorizedOAuth2Error, self).generate(request)


class MissingParameterError(AuthorizationError):
    """ Error due to a missing parameter. """
    def __init__(self, name=None, state=None):
        if name is None:
            message = 'A required parameter was missing from the request'
        else:
            message = 'Request was missing the \'{name}\' parameter'.format(name=name)
        super(MissingParameterError, self).__init__(BAD_REQUEST, 'invalid_request',
                                                    message, state=state)


class InvalidParameterError(AuthorizationError):
    """ Error due to an invalid parameter. """
    def __init__(self, name=None, state=None):
        if name is None:
            message = 'A required parameter was invalid'
        else:
            message = 'The parameter \'{name}\' is invalid'.format(name=name)
        super(InvalidParameterError, self).__init__(BAD_REQUEST, 'invalid_request',
                                                    message, state=state)


class InsecureConnectionError(AuthorizationError):
    """ Error because a request was made over an insecure connection which was not permitted. """
    def __init__(self, state=None):
        message = 'OAuth 2.0 requires requests over HTTPS'
        super(InsecureConnectionError, self).__init__(BAD_REQUEST, 'invalid_request',
                                                      message, state=state)


class UnsupportedResponseTypeError(AuthorizationError):
    """ Error because a request requested an unsupported response type. """
    def __init__(self, responseType, state=None):
        message = 'Obtaining an authorization code using this method ' \
                  'is not supported: ' + responseType
        super(UnsupportedResponseTypeError, self).__init__(
            BAD_REQUEST, 'unsupported_response_type', message, state=state)


class ServerError(AuthorizationError):
    """ General server error. """
    def __init__(self, state=None):
        message = 'An unexpected condition was encountered and the request could not get fulfilled.'
        super(ServerError, self).__init__(
            SERVICE_UNAVAILABLE, 'server_error', message, state=state)


class TemporarilyUnavailableError(AuthorizationError):
    """ Error because of a temporary failure. """
    def __init__(self, state=None):
        message = 'The request could not be handled due to a temporary overloading or maintenance.'
        super(TemporarilyUnavailableError, self).__init__(
            BAD_REQUEST, 'temporarily_unavailable', message, state=state)


class MultipleParameterError(AuthorizationError):
    """ Error because a request contained multiple values for a parameter. """
    def __init__(self, parameter=None, state=None):
        message = 'The request contained a duplicate parameter'
        if parameter is not None:
            message += ': ' + parameter
        super(MultipleParameterError, self).__init__(
            BAD_REQUEST, 'invalid_request', message, state=state)


class MalformedParameterError(AuthorizationError):
    """ Error due to a malformed parameter. """
    def __init__(self, name, state=None):
        message = 'The parameter \'{name}\' was malformed'.format(name=name)
        super(MalformedParameterError, self).__init__(
            BAD_REQUEST, 'invalid_request', message, state=state)


class UnauthorizedClientError(AuthorizationError):
    """ Error because a client tried to use a grant type it was not authorized to use. """
    def __init__(self, grantType=None, state=None):
        message = 'The authenticated client is not authorized to use this authorization grant type'
        if grantType is not None:
            message += ': ' + grantType
        super(UnauthorizedClientError, self).__init__(
            BAD_REQUEST, 'unauthorized_client', message, state=state)


class InvalidRedirectUriError(OAuth2Error):
    """ Error because a given redirect uri is not valid or allowed for the client. """
    def __init__(self):
        message = 'Invalid redirection URI'
        super(InvalidRedirectUriError, self).__init__(BAD_REQUEST, 'invalid_request', message)


class InvalidClientIdError(UnauthorizedOAuth2Error):
    """ Error because a given client id does not identify a known client. """
    def __init__(self):
        message = 'Invalid client_id'
        super(InvalidClientIdError, self).__init__(UNAUTHORIZED, 'invalid_client', message)


class NoClientAuthenticationError(UnauthorizedOAuth2Error):
    """ Error because a request did not contain any client authentication but was expected to. """
    def __init__(self):
        message = 'The request was missing client authentication'
        super(NoClientAuthenticationError, self).__init__(UNAUTHORIZED, 'invalid_client', message)


class InvalidClientAuthenticationError(UnauthorizedOAuth2Error):
    """ Error because the client authentication in the request are invalid. """
    def __init__(self):
        super(InvalidClientAuthenticationError, self).__init__(
            UNAUTHORIZED, 'invalid_client', 'The client could not get authenticated.')


class InvalidTokenError(OAuth2Error):
    """ Error due to an invalid token. """
    def __init__(self, tokenType):
        message = 'The provided {type} is invalid'.format(type=tokenType)
        super(InvalidTokenError, self).__init__(BAD_REQUEST, 'invalid_grant', message)


class DifferentRedirectUriError(OAuth2Error):
    """
    Error because a different redirect uri was passed to the token endpoint.
    Expected the redirect uri that was used with the authorization endpoint.
    """
    def __init__(self):
        message = 'The redirect_uri does not match the ' \
                  'redirection URI used in the authorization request'
        super(DifferentRedirectUriError, self).__init__(BAD_REQUEST, 'invalid_grant', message)


class InvalidScopeError(AuthorizationError):
    """ Error due to an invalid scope. """
    def __init__(self, scope, state=None):
        if isinstance(scope, list):
            scope = ' '.join(scope)
        if isinstance(scope, bytes):
            scope = scope.decode('utf-8', errors='replace')
        message = 'The provided scope is invalid: ' + scope
        super(InvalidScopeError, self).__init__(BAD_REQUEST, 'invalid_scope', message, state=state)


class UnsupportedGrantTypeError(OAuth2Error):
    """ Error because a request requested an unsupported grant type. """
    def __init__(self, grantType=None):
        message = 'The authorization grant type is not supported'
        if grantType is not None:
            message += ': ' + grantType
        super(UnsupportedGrantTypeError, self).__init__(
            BAD_REQUEST, 'unsupported_grant_type', message)


class MultipleClientCredentialsError(OAuth2Error):
    """ Error because a request contained multiple client credentials. """
    def __init__(self):
        super(MultipleClientCredentialsError, self).__init__(
            BAD_REQUEST, 'invalid_request', 'The request contained multiple client credentials')


class MultipleClientAuthenticationError(OAuth2Error):
    """ Error because a request utilized more than one mechanism for authentication. """
    def __init__(self):
        message = 'The request utilized more than one mechanism for authenticating the client'
        super(MultipleClientAuthenticationError, self).__init__(
            BAD_REQUEST, 'invalid_request', message)


class MalformedRequestError(OAuth2Error):
    """ Error due to a generally malformed request. """
    def __init__(self, msg=None):
        message = 'The request was malformed'
        if msg is not None:
            message += ': ' + msg
        super(MalformedRequestError, self).__init__(BAD_REQUEST, 'invalid_request', message)


class UserDeniesAuthorization(AuthorizationError):
    """ Error because the user denied a authorization request. """
    def __init__(self, state=None):
        message = 'The resource owner denied the request'
        super(UserDeniesAuthorization, self).__init__(OK, 'access_denied', message, state=state)


class MissingTokenError(OAuth2RequestError):
    """ Error because a request did not contain an access token but was expected to. """
    def __init__(self, scope):
        message = 'No access token provided'
        super(MissingTokenError, self).__init__(
            UNAUTHORIZED, 'invalid_request', message, scope, addDetailsToHeader=False)


class InvalidTokenRequestError(OAuth2RequestError):
    """ Error because the token is invalid. """
    def __init__(self, scope):
        message = 'The access token is invalid'
        super(InvalidTokenRequestError, self).__init__(
            UNAUTHORIZED, 'invalid_token', message, scope)


class InsufficientScopeRequestError(OAuth2RequestError):
    """ Error because the token does not grant access to the scope. """
    def __init__(self, scope):
        message = 'The request requires higher privileges than provided by the access token'
        super(InsufficientScopeRequestError, self).__init__(
            FORBIDDEN, 'insufficient_scope', message, scope)


class MultipleTokensError(OAuth2RequestError):
    """ Error because a request contained multiple tokens. """
    def __init__(self, scope):
        message = 'The request contained multiple access tokens'
        super(MultipleTokensError, self).__init__(BAD_REQUEST, 'invalid_request', message, scope)
