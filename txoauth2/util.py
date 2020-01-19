# Copyright (c) Sebastian Scholz
# See LICENSE for details.
""" Utility methods. """

try:
    from __builtin__ import basestring as StringType, long as LongType
except ImportError:
    StringType = str
    LongType = int
try:
    from urlparse import urlparse, parse_qsl, urlunparse
    from urllib import urlencode
except ImportError:
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse


def isAnyStr(val):
    """
    :param val: The value to check
    :return: If it is a string value (includes unicode).
    """
    return isinstance(val, StringType)


def isIntType(val):
    """
    :param val: The value to check
    :return: If it is a number value (includes long).
    """
    return isinstance(val, (int, LongType))


def addToUrl(url, query=None, fragment=None):
    """
    Add the query and or fragment to the url, preserving an existing query
    and discarding an existing fragment.
    :param url: The base url.
    :param query: The query to add to the base url as a dict.
    :param fragment: The fragment to add to the base url as a dict.
    :return: The new url.
    """
    urlParts = list(urlparse(url))
    if query is not None:
        urlQuery = dict(parse_qsl(urlParts[4]))
        urlQuery.update(query)
        urlParts[4] = urlencode(urlQuery)
    if fragment is not None:
        urlParts[5] = urlencode(fragment)
    return urlunparse(urlParts)
