import json
import os
import requests
import logging

import flask
import httplib2

from oauth2client import client

# Required environment variables
GOOGLE_CLIENT_ID = os.getenv("Google_client_id", None)
GOOGLE_SECRET = os.getenv("Google_secret", None)
GOOGLE_SCOPE = os.getenv("Google_scope", None)
SERVICE_HOST = os.environ.get("service_host", "jsonplaceholder.typicode.com")
SERVICE_PORT = os.environ.get("service_port", None)

app = flask.Flask(__name__)
app.logger.info("Application initialized")

def generate_response_content(response):
    """ Iterates over the response data. Requires `stream=True` set on the 
        request, this avoids reading the content at once into memory for large
        responses.
    """
    app.logger.debug("Iterating over response content")
    for chunk in response.iter_content(chunk_size=1024, decode_unicode=True):
        yield chunk
   
def get_endpoint_response(request, service_host=SERVICE_HOST, port=SERVICE_PORT):
    """ Given a Flask request object, service host and a port - return the 
	    contents of the URL. Include authentication headers in forwarded request
	    to allow service to authorize. 
        
        Inspired in part by https://gist.github.com/gear11/8006132
    """
    if port:
        url = 'http://{}:{}/{}'.format(service_host, port, "users")
    else:
        url = 'http://{}/{}'.format(service_host, "users")
	
	app.logger.debug("Updating Authorization header")
	email = json.loads(flask.session['credentials'])['id_token']['email']
	headers_with_auth = {}
	for key, value in request.headers:
	    headers_with_auth[key] = value
	headers_with_auth.update({"Authorization": email})

	app.logger.debug("Requesting {}".format(url))
	r = requests.get(url, stream=True, params=request.args,
	                 headers=headers_with_auth)
	app.logger.debug("Request response: {}".format(r))
	return flask.Response(generate_response_content(r), r.headers)


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
        try:
            return get_endpoint_response(flask.request, SERVICE_HOST,
                                         SERVICE_PORT)
        except Exception, e:
            if "certificate verify failed" in str(e):
                flask.abort(505, str(e))
            else:
                flask.abort(500, str(e))
            


@app.route('/oauth2callback')
def oauth2callback():
	""" Send user to Google for authentication"""

	google_redirect_uri = "{}oauth2callback".format(flask.request.url_root)
	
	""" OAuth2WebServerFlow:
	    https://developers.google.com/api-client-library/python/guide/aaa_oauth#OAuth2WebServerFlow
    """
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
