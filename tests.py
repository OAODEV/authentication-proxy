import json
import unittest
import os
from datetime import datetime

from authentication_proxy import update_header, get_url_to_proxy

from flask import Flask


class TestiAdOpsUsers(unittest.TestCase):

    def setUp(self):

        # Replace environment variables with testing value
        self.env_var_map = [('Google_client_id', 'fAk3_cL13Nt_1D'),
                            ('Google_secret', 'fAk3_53CReT'),
                            ('Google_scope', 
                             'http://fAk3.sC0p3.com/3nDp01nT1 http://fAk3.sC0p3.com/3nDp01nT2'),
                            ('service_host', '123.4.5.6'),
                            ('service_port', '1234'),
                            ('service_key', 'fAk3_k3Y')
                           ]
        self.env_vars = {}
        for env_var in self.env_var_map:
            # Store original environment variable
            self.env_vars[env_var[0]] = os.environ.get(env_var[0], None)
            # Set environment variable to testing value
            os.environ[env_var[0]] = env_var[1]
        
        self.app = Flask('auth-proxy')
        self.client = self.app.test_client()

    def tearDown(self):
        """Restores original environment variables"""

        for env_var in self.env_var_map:
            if self.env_vars[env_var[0]]:
                os.environ[env_var[0]] = self.env_vars[env_var[0]]
            else: 
                del os.environ[env_var[0]]

    def test_sanity(self):
        """Proves test suite is working"""

        four = 2+2
        self.assertEqual(four, 4, "Um ... 2+2 doesn't equal 4?")
        
    def test_update_header(self):
        """ Verifies that the header that goes in to update_header is returned
            with additional Authorization header (and only that update) """

        fake_session = {}
        fake_session['credentials'] = '{"id_token": {"email":"fake@email.com"}}'
        
        fake_header = {'Fake Header Field': 'Fake Header Value'}
        
        headers_with_auth = update_header(fake_header, fake_session)
        expected_headers = fake_header
        expected_headers['X-Authenticated-Email']='fake@email.com'
        
        self.assertEqual(headers_with_auth, expected_headers)

    
    def test_get_url_to_proxy(self):
        """ Verifies that URL comes back as expected given the service host,
            port (optional) and as the request's location (optional)
            (derived from request's path) """
        
        returned_url = get_url_to_proxy('host', 1234, 'request/path/to/object')
        expected_url = 'http://host:1234/request/path/to/object'
        self.assertEqual(returned_url, expected_url)
        
        returned_url = get_url_to_proxy('host')
        expected_url = 'http://host/'
        self.assertEqual(returned_url, expected_url)
        
        returned_url = get_url_to_proxy('host', 1234)
        expected_url = 'http://host:1234/'
        self.assertEqual(returned_url, expected_url)
        
        returned_url = get_url_to_proxy('host', None, 'request/path/to/object')
        expected_url = 'http://host/request/path/to/object'
        self.assertEqual(returned_url, expected_url)



if __name__ == '__main__':
    unittest.main()
