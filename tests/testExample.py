import os
import sys

from twisted.trial import unittest
from tests import DummySite

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'example')))
from main import setupTestServerResource


class ExampleTestCase(unittest.TestCase):
    server = None

    def setUp(self):
        self.server = DummySite(setupTestServerResource())

    def testClockResourceNoAccessToken(self):
        response = self.server.get('clock')
        def callback(result):
            print(dir(result))
            print(result.value())
            self.assertEqual(401, result.responseCode)
            header = result.getHeader('WWW-Authenticate')
            self.assertIsNotNone(header)
            self.assertTrue(header.startsWith('Bearer'))

            self.assertNotSubstring('<html><body>', result.value())
        response.addCallback(callback)
        return response
