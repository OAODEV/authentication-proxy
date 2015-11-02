import unittest
import os

from flask import Flask

from authentication_proxy import update_header, get_url_to_proxy, get_secrets

class TestiAdOpsUsers(unittest.TestCase):

    def setUp(self):
        self.app = Flask('auth-proxy')
        self.client = self.app.test_client()


    def tearDown(self):
        """Restores original environment variables"""
        pass

    def test_sanity(self):
        """Proves test suite is working"""

        four = 2+2
        self.assertEqual(four, 4, "Um ... 2+2 doesn't equal 4?")

    def test_get_secrets(self):
        """ get secrets should return a dict of secrets """
        secrets = get_secrets()
        self.assertEqual(secrets['google-client-id'], 'placeholder')
        self.assertEqual(secrets['google-secret'], 'placeholder')
        self.assertEqual(secrets['secret-key'], '')

    def test_update_header(self):
        """ Verifies that the header that goes in to update_header is returned
            with additional Authorization header (and only that update) """

        fake_session = {}
        fake_session['credentials'] = '{"id_token": {"email":"fake@email.com"}}'

        fake_header = {'Fake Header Field': 'Fake Header Value'}

        headers_with_auth = update_header(fake_header, fake_session)
        expected_headers = fake_header
        expected_headers['X-Authenticated-Email'] = 'fake@email.com'

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
