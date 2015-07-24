import json
import os
import requests
import logging
import sys

import flask
from oauth2client import client

# Set environment variables
GOOGLE_SCOPE = os.environ.get(
    "Google_scope",
    "https://www.googleapis.com/auth/userinfo.email " + \
    "https://www.google.com/apis/ads/publisher " + \
    "https://www.googleapis.com/auth/plus.me"
)
SERVICE_HOST = os.environ.get("service_host", '127.0.0.1')
SERVICE_PORT = os.environ.get("service_port", '8000')
SECRETS_PATH = os.environ.get("secrets_path", '/var/secrets')

ENV = os.environ.get("Environment_name", None)
if ENV in ['production', 'stage']:
    DEBUG = False
else:
    DEBUG = True

def get_secrets():
    secrets = {}
    for name in ['google-client-id', 'google-secret', 'secret-key']:
        path = os.path.join(SECRETS_PATH, name)

        with open(path, 'r') as secret_file:
            secrets[name] = secret_file.read()
    return secrets

secrets = get_secrets()
GOOGLE_CLIENT_ID = secrets.get('google-client-id', '').strip()
GOOGLE_SECRET = secrets.get('google-secret', '').strip()
FLASK_SECRET_KEY = secrets.get('secret-key', '').strip()
if not FLASK_SECRET_KEY:
    FLASK_SECRET_KEY = os.urandom(32).encode('hex').strip()


app = flask.Flask(__name__)


std_out = logging.StreamHandler(sys.stdout)
std_out.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
std_out.setFormatter(formatter)
app.logger.addHandler(std_out)

app.logger.info("Application initialized")


# Library Functions
def update_header(headers, session):
    """ Given Flask request headers and session, creates a new set of headers
        with `X-Authenticated-Email` header. """

    # Creating a copy of headers
    headers_with_auth = {}
    for key, value in headers.items():
        headers_with_auth[key] = value

    app.logger.debug("Updating Authorization header")
    email = json.loads(session['credentials'])['id_token']['email']
    # In most situations, this value should be signed
    headers_with_auth.update({"X-Authenticated-Email": str(email)})

    return headers_with_auth


def get_url_to_proxy(service_host, port=None, location=None):
    """ Give a service host (URI), port and location, returns URL to proxy"""

    if not location:
        location = ''

    if port:
        url = 'http://{}:{}/{}'.format(service_host, port, location)
    else:
        url = 'http://{}/{}'.format(service_host, location)
    return url


def get_endpoint_response(request, session, location, service_host=SERVICE_HOST,
                          port=SERVICE_PORT):
    """ Given a Flask request object, session, service host and a port - return
        the contents of the URL. Include authentication headers in forwarded
        request to allow service to authorize.

        Inspired in part by https://gist.github.com/gear11/8006132
    """

    url = get_url_to_proxy(service_host, port, location)
    headers_with_auth = update_header(request.headers, session)

    app.logger.debug("Requesting {}".format(url))

    r = {}
    try:
        if request.method == 'POST':  # Create
            r = requests.post(url, stream=True, params=session['args'],
                              headers=headers_with_auth, verify=True)
        elif request.method == 'GET':  # Retrieve
            r = requests.get(url, stream=True, params=session['args'],
                             headers=headers_with_auth, verify=True)
        elif request.method == 'PUT':  # Update
            r = requests.put(url, stream=True, params=session['args'],
                             headers=headers_with_auth, verify=True)
        elif request.method == 'DELETE':  # Delete
            r = requests.delete(url, stream=True, params=session['args'],
                                headers=headers_with_auth, verify=True)
        app.logger.debug("Request response: {}".format(r))
        return r.text, r.status_code, r.headers.items()

    except requests.exceptions.SSLError, e:
        flask.abort(505, "SSL certificate on destination domain failed "
                         + "verification")
    except Exception, e:
        if r:
            app.logger.error("{} - {}: {}".format(str(e), r.status_code, r.reason))
            flask.abort(r.status_code, r.reason)
        else:
            app.logger.error(str(e))
            flask.abort(500, str(e))


# Routes
# Catch-all routing inspired by http://flask.pocoo.org/snippets/57/
@app.route('/', methods=['POST', 'GET', 'PUT', 'POST'],
           defaults={'location': None})
@app.route('/<path:location>', methods=['POST', 'GET', 'PUT', 'POST'])
def index(location=None):
    """ Authenticate & return endpoint response for user

        Google OAuth2 client documentation:
         * https://developers.google.com/api-client-library/python/auth/web-app
    """
    if location:
        flask.session['location'] = location

    if flask.request.args:
        flask.session['args'] = flask.request.args
    elif flask.request.form:
        flask.session['args'] = flask.request.form

    if 'credentials' not in flask.session:
        app.logger.debug("No credentials, initializing OAuth2workflow")
        return flask.redirect(flask.url_for('oauth2callback'))

    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])

    if credentials.access_token_expired:
        app.logger.debug("{} token expired, initializing OAuth2workflow"
                         .format(credentials.id_token['email']))
        return flask.redirect(flask.url_for('oauth2callback'))
    else:
        app.logger.debug("{} authenticated"
                         .format(credentials.id_token['email']))
        return get_endpoint_response(flask.request, flask.session,
                                     flask.session['location'], SERVICE_HOST,
                                     SERVICE_PORT)


@app.route('/oauth2callback')
def oauth2callback():
    """ Send user to Google for authentication"""

    app.logger.debug("Create redirect URI for Google")
    google_redirect_uri = "{}oauth2callback".format(flask.request.url_root)

    # https://developers.google.com/api-client-library/python/guide/aaa_oauth#OAuth2WebServerFlow
    app.logger.debug("Create OAuth2WebServerFlow")
    flow = client.OAuth2WebServerFlow(client_id=GOOGLE_Client_ID,
                                      client_secret=GOOGLE_SECRET,
                                      scope=GOOGLE_SCOPE,
                                      redirect_uri=google_redirect_uri)

    if 'code' not in flask.request.args:
        app.logger.debug("Sending user to Google for authentication")
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    else:
        app.logger.debug("Exchanging an auth code for a Credentials object")
        auth_code = flask.request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        flask.session['credentials'] = credentials.to_json()
        app.logger.debug("User has 'logged in' via oauth2callback")
        return flask.redirect(flask.url_for('index'))

if __name__ == '__main__':

    for env_var in (GOOGLE_CLIENT_ID, GOOGLE_SECRET, GOOGLE_SCOPE, SERVICE_HOST,
                    FLASK_SECRET_KEY):
        if not env_var or env_var == 'placeholder':
            msg = "Missing required settings."
            app.logger.error(msg)
            if not DEBUG:
                sys.exit("ERROR: {}".format(msg))

    app.secret_key = FLASK_SECRET_KEY
    app.debug = DEBUG
    app.run(host="0.0.0.0", port=5000)
