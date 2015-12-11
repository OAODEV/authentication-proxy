import unittest
import os
import uuid

from flask import (
    Flask,
    request,
    session,
)
from mock import (
    MagicMock,
    patch,
)

from authentication_proxy import (
    authentic_cci_token,
    get_endpoint_response,
    get_secrets,
    get_url_to_proxy,
    update_header,
)

class TestiAdOpsUsers(unittest.TestCase):

    def setUp(self):
        self.app = Flask('auth-proxy')
        self.app.secret_key = 'testkey'
        self.client = self.app.test_client()

    def tearDown(self):
        pass

    def test_sanity(self):
        """ Proves test suite is working """

        four = 2+2
        self.assertEqual(four, 4, "Um ... 2+2 doesn't equal 4?")

    def test_get_endpoint_response(self):
        """ Should forward requests and responses """

        def test_path(path, method):
            # set up
            update_header_patcher = patch(
                'authentication_proxy.update_header',
                return_value={'X-Mock-Header': 'foo'},
            )
            mock_update_header = update_header_patcher.start()
            mock_response = MagicMock()
            post_patcher = patch(
                'authentication_proxy.requests.post',
                return_value=mock_response,
            )
            mock_post = post_patcher.start()
            get_patcher = patch(
                'authentication_proxy.requests.get',
                return_value=mock_response,
            )
            mock_get = get_patcher.start()
            put_patcher = patch(
                'authentication_proxy.requests.put',
                return_value=mock_response,
            )
            mock_put = put_patcher.start()
            delete_patcher = patch(
                'authentication_proxy.requests.delete',
                return_value=mock_response,
            )
            mock_delete = delete_patcher.start()

            mocks = {
                "POST": mock_post,
                "GET": mock_get,
                "PUT": mock_put,
                "DELETE": mock_delete,
            }

            with self.app.test_request_context(path, method=method):
                if request.args:
                    session['args'] = request.args

                # run SUT
                text, status, headers = get_endpoint_response(
                    request,
                    session,
                    path,
                    'mock_host',
                    '1234',
                )

                params = None
                if request.args:
                    params = request.args

                # confirm assumptions
                mocks[method].assert_called_once_with(**{
                    'url': 'http://mock_host:1234/{}'.format(path),
                    'stream': True,
                    'params': params,
                    'headers': {'X-Mock-Header': 'foo'},
                    'verify': True,
                })

            # tear down
            patch.stopall()

        # test each path with and without trailing slash, and with args
        test_paths = [
            'path', 'path/', 'path?a=b',
            'a/b/c', 'a/b/c/', 'a/b/c?a=b',
            '/', '//', '/?ab=cd'
        ]
        methods = ["POST", "GET", "PUT", "DELETE"]
        # test all pairs of paths and methods
        for p, m in [(p, m) for p in test_paths for m in methods]:
            test_path(p, m)

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

        """
        this is testing correctly now, but the function update_header could
        reimplement and break without this test failing.
        I think this test would pass even if it were implemented like this

        def update_header(h, s):
            return h

        sinse fake_header is being passed around as a reference, if we just pass
        that reference back we end up updating it with soemthing and then check
        that it is itself.
        """
        headers_with_auth = update_header(fake_header, fake_session)
        expected_headers = fake_header
        expected_headers['X-Authenticated-Email'] = 'fake@email.com'

        self.assertEqual(headers_with_auth, expected_headers)

        fake_ci_session = {}
        fake_ci_session['credentials'] = '{"authenticated_token": "CI"}'
        headers_with_ci_auth = update_header({}, fake_ci_session)
        self.assertEqual(headers_with_ci_auth, {"X-Authenticated-Token": "CI"})

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

    def test_token_authentication(self):
        """ Verifies that the token authentication function will accept correct
            tokens and reject incorrect tokens """
        self.assertTrue(authentic_cci_token("placeholder"))
        self.assertFalse(authentic_cci_token("notplaceholder"))


if __name__ == '__main__':
    unittest.main()
