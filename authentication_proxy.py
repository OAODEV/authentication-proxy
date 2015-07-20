import json
import os
import requests
import logging
import sys

import flask
import httplib2
from urllib2 import HTTPError

from oauth2client import client

# Required environment variables
GOOGLE_CLIENT_ID = os.environ.get("Google_client_id", None)
GOOGLE_SECRET = os.environ.get("Google_secret", None)
GOOGLE_SCOPE = os.environ.get("Google_scope", None)
SERVICE_HOST = os.environ.get("service_host", None)
SERVICE_PORT = os.environ.get("service_port", None)

app = flask.Flask(__name__)


std_out = logging.StreamHandler(sys.stdout)
std_out.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
std_out.setFormatter(formatter)
app.logger.addHandler(std_out)

app.logger.info("Application initialized")

# Enforces required environment variables
for env_var in (GOOGLE_CLIENT_ID, GOOGLE_SECRET, GOOGLE_SCOPE, SERVICE_HOST):
    if not env_var:
        msg = "Not all required environment variables are available."
        app.logger.error(msg)
        sys.exit("ERROR: {}".format(msg))

# Library Functions
def update_header(headers, session):
    """ Given Flask request headers and session, creates a new set of headers
        with Authorization information. """

    # Creating a copy of headers
    headers_with_auth = {}
    for key, value in headers.items():
	    headers_with_auth[key] = value

    app.logger.debug("Updating Authorization header")
    email = json.loads(session['credentials'])['id_token']['email']
    # In most situations, this value should be signed
    headers_with_auth.update({"Authorization": str(email)}) 

    return headers_with_auth


def get_url_to_proxy(service_host, port=None, location=None):
    """ Give a service host (URI), port and location, returns URL to proxy"""

    if not location:
        location=''

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
    try:
        r = {}
        r = requests.get(url, stream=True, params=session['args'],
                         headers=request.headers, verify=True)
        app.logger.debug("Request response: {}".format(r))
        return r.text, r.status_code, r.headers.items()

    except requests.exceptions.SSLError, e:
        flask.abort(505, "SSL certificate on destination domain failed "\
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
@app.route('/', defaults={'location': None})
@app.route('/<path:location>')
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
        return get_endpoint_response(flask.request, flask.session, location,
                                         SERVICE_HOST, SERVICE_PORT)
            

@app.route('/oauth2callback')
def oauth2callback():
    """ Send user to Google for authentication"""

    app.logger.debug("Create redirect URI for Google")
    google_redirect_uri = "{}oauth2callback".format(flask.request.url_root)

    # https://developers.google.com/api-client-library/python/guide/aaa_oauth#OAuth2WebServerFlow
    app.logger.debug("Create OAuth2WebServerFlow")
    flow = client.OAuth2WebServerFlow(client_id=GOOGLE_CLIENT_ID,
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
		return flask.redirect(flask.url_for('index'))
				


if __name__ == '__main__':
	import uuid
	app.secret_key = str(uuid.uuid4())
	app.debug = True
	app.run()
