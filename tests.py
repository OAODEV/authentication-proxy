import json
import unittest
import os
from datetime import datetime

from flask import Flask


class TestiAdOpsUsers(unittest.TestCase):

    def setUp(self):

        # Replace environment variables with testing value
        self.env_google_secret = os.environ.get('Google_secret', None)
        os.environ['Google_secret'] = 'fAk3_53CReT'
        
        self.app = Flask('auth-proxy')
        self.client = self.app.test_client()

    def tearDown(self):
        '''Restores original environment variables'''

        if self.env_google_secret:
            os.environ['Google_secret'] = self.env_google_secret

    def test_sanity(self):
        '''Proves test suite is working'''

        four = 2+2
        self.assertEqual(four, 4, "Um ... 2+2 doesn't equal 4?")



if __name__ == '__main__':
    unittest.main()
