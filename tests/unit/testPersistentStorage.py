""" Tests for a persistent storage. """

import time

from txoauth2.imp import DictNonPersistentStorage

from tests import TwistedTestCase


class Abstract:
    """ Wrapper for the abstract PersistentStorageTest to hide it during test discovery. """

    class PersistentStorageTest(TwistedTestCase):
        """
        An abstract test case for PersistentStorage implementations. A subclass must
        call setupPersistentStorage with an instance of the persistent storage to test.
        """
        _PERSISTENT_STORAGE = None

        @classmethod
        def setupPersistentStorage(cls, persistentStorage):
            """
            Set the persistent storage implementation to use for the tests.
            :param persistentStorage: The persistent storage implementation to test.
            """
            cls._PERSISTENT_STORAGE = persistentStorage

        def testPut(self):
            """
            Test that the persistent storage can correctly store data.
            """
            data = {
                'testPutKey': 'testData',
                'testPutKey2': {'data': 'testData'},
                'testPutKey3': {'strData': 'testData', 'intData': 1},
                'testPutKey4': {'strData': 'testData', 'listData': [1, 2]},
                'testPutKey5': {'strData': 'testData', 'dictData': {'int': 2}},
            }
            for dataKey, dataValue in data.items():
                self._assertNotContains(dataKey,
                                        msg='Expected that the persistent storage would not '
                                            'contain the test key before it was stored.')
                self._PERSISTENT_STORAGE.put(dataKey, dataValue)
                self._assertContains(dataKey, dataValue,
                                     invalidKeyMsg='Expected the persistent storage to '
                                                   'contain the data after it was stored.',
                                     invalidDataMsg='Expected the persistent storage to return '
                                                    'the same value that was stored.')

        def testPop(self):
            """ Test that the persistent storage correctly removes data. """
            key = 'testPopKey'
            data = 'testPopData'
            self._PERSISTENT_STORAGE.put(key, data)
            self._assertContains(key, data,
                                 invalidKeyMsg='Expected the persistent storage to be '
                                               'able to remove the data after it was stored.',
                                 invalidDataMsg='Expected the persistent storage to return '
                                                'the correct data that was removed.')
            self._assertNotContains(key, msg='Expected that the persistent storage would not '
                                             'contain the data after it was removed.')

        def testDataOverwrite(self):
            """
            Test that the persistent storage correctly overwrites an existing data entry.
            """
            key = 'overwriteDataKey'
            oldData = 'old data'
            newData = 'new data'
            self._PERSISTENT_STORAGE.put(key, oldData)
            self._PERSISTENT_STORAGE.put(key, newData)
            self._assertContains(key, newData,
                                 invalidKeyMsg='Expected the persistent storage to contain the key '
                                               'if a new entry was written over a previous one.',
                                 invalidDataMsg='Expected the persistent storage to store the '
                                                'new data when overwriting an old data entry.')

        def testExpireTime(self):
            """ Test that the persistent storage correctly expires the data. """
            data = 'data'
            noExpireKey = 'noExpireKey'
            longLiveKey = 'longLiveKey'
            expiredKeys = ['expiredKey1', 'expiredKey2', 'expiredKey3']
            hasExpiredKey = 'expiredKey'
            for key in expiredKeys:
                self._PERSISTENT_STORAGE.put(key, data, expireTime=time.time() + 1)
            self._PERSISTENT_STORAGE.put(noExpireKey, data)
            self._PERSISTENT_STORAGE.put(longLiveKey, data, expireTime=time.time() + 600)
            self._PERSISTENT_STORAGE.put(hasExpiredKey, data, expireTime=time.time() - 10)
            for key in expiredKeys:
                self._assertContains(
                    key, data, invalidKeyMsg='Expected the persistent storage to contain the data '
                                             'that will expire in a few seconds but has not yet.')
                self._PERSISTENT_STORAGE.put(key, data, expireTime=time.time() + 1)
            self._assertContains(
                noExpireKey, data, invalidKeyMsg='Expected the persistent storage to '
                                                 'contain the data that will never expire.')
            self._PERSISTENT_STORAGE.put(noExpireKey, data)
            self._assertContains(
                longLiveKey, data, invalidKeyMsg='Expected the persistent storage to contain '
                                                 'the data that has not expired.')
            self._PERSISTENT_STORAGE.put(longLiveKey, data, expireTime=time.time() + 600)
            self._assertNotContains(hasExpiredKey, msg='Expected the persistent storage to '
                                                       'not contain the data that has expired.')
            time.sleep(1.5)
            for key in expiredKeys:
                self._assertNotContains(key, msg='Expected the persistent storage to '
                                                 'not contain the data that has expired.')
            self._assertContains(
                noExpireKey, data, invalidKeyMsg='Expected the persistent storage to '
                                                 'contain the data that will never expire.')
            self._assertContains(
                longLiveKey, data, invalidKeyMsg='Expected the persistent storage to contain '
                                                 'the data that has not expired.')

        def _assertContains(self, key, expectedData, invalidKeyMsg=None, invalidDataMsg=None):
            if invalidKeyMsg is None:
                invalidKeyMsg = 'Expected the persistent storage to contain the key.'
            if invalidDataMsg is None:
                invalidDataMsg = 'Expected the persistent storage to contain the expected data.'
            try:
                storedData = self._PERSISTENT_STORAGE.pop(key)
            except KeyError:
                self.fail(msg=invalidKeyMsg)
            self.assertEqual(expectedData, storedData, msg=invalidDataMsg)

        def _assertNotContains(self, key, msg=None):
            try:
                self._PERSISTENT_STORAGE.pop(key)
                self.fail(msg)
            except KeyError:
                pass


class DictNonPersistentStorageTest(Abstract.PersistentStorageTest):
    """ Test the DictNonPersistentStorage. """

    @classmethod
    def setUpClass(cls):
        cls.setupPersistentStorage(DictNonPersistentStorage())
