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
SERVICE_HOST = os.environ.get("service_host", "jsonplaceholder.typicode.com")
SERVICE_PORT = os.environ.get("service_port", None)

app = flask.Flask(__name__)
app.logger.info("Application initialized")

for env_var in (GOOGLE_CLIENT_ID, GOOGLE_SECRET, GOOGLE_SCOPE):
    if not env_var:
        sys.exit("ERROR: Not all required environment variables are available.")

# Library Functions
def generate_response_content(response):
    """ Iterates over the response data. Requires `stream=True` set on the 
        request, this avoids reading the content at once into memory for large
        responses.
    """
    app.logger.debug("Iterating over response content")
    for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
        yield chunk

def update_header(headers, session):
    """ Given Flask request headers and session, creates a new set of headers
        with Authorization information. """

    # Creating a copy of headers
    headers_with_auth = {}
    for key, value in headers:
	    headers_with_auth[key] = value

    app.logger.debug("Updating Authorization header")
    email = json.loads(session['credentials'])['id_token']['email']
    # In most situations, this value should be signed
    headers_with_auth.update({"Authorization": email}) 

    return headers_with_auth
    
   
def get_endpoint_response(request, session, service_host=SERVICE_HOST,
                          port=SERVICE_PORT):
    """ Given a Flask request object, session, service host and a port - return
        the contents of the URL. Include authentication headers in forwarded 
        request to allow service to authorize. 
        
        Inspired in part by https://gist.github.com/gear11/8006132
    """
    if port:
        url = 'https://{}:{}/{}'.format(service_host, port, "users")
    else:
        url = 'https://{}/{}'.format(service_host, "users")
	
	headers_with_auth = update_header(request.headers, session)

	app.logger.debug("Requesting {}".format(url))
    try:
        r = requests.get(url, stream=True, params=request.args,
                         headers=headers_with_auth, verify=True)
        r.raise_for_status()
        app.logger.debug("Request response: {}".format(r))
        return flask.Response(generate_response_content(r), r.headers)
    except requests.exceptions.SSLError, e:
        flask.abort(505, "SSL certificate on destination domain failed "\
                         + "verification")
    except Exception, e: 
        app.logger.error("{}: {}".format(r.status_code, r.reason))
        flask.abort(r.status_code, r.reason)


# Routes
@app.route('/')
def index():
    """ Authenticate & return endpoint response for user 
    
        Google OAuth2 client documentation:
         * https://developers.google.com/api-client-library/python/auth/web-app
    """

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
