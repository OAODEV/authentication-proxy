import json
import os
import requests

import flask
import httplib2

from oauth2client import client


GOOGLE_CLIENT_ID = os.getenv("Google_client_id", None)
GOOGLE_SECRET = os.getenv("Google_secret", None)
GOOGLE_SCOPE = os.getenv("Google_scope", None)

APPROVED_HOSTS = ["iadops.com", "matturban.com"]


app = flask.Flask(__name__)


def is_approved_host(url):
    """ Is the referring or proxied URL whitelisted for use?"""
    approved = False
    for host in APPROVED_HOSTS:
    	if host in url:
    		 approved = True
    return approved

   
def get_endpoint_response(url, request):
	""" Given a URL and a Flask request object, return the contents of the URL.
        Include authentication headers in forwarded request to allow URL to
        authorize. 
        
        Inspired in part by https://gist.github.com/gear11/8006132"""
	url = 'https://{}'.format(url)
	if not is_approved(url):
		# URL is not approved
		abort(403, "The referring or requested URL ({}) is not " \
				   + "whitelisted for use by this authentication proxy."
				   .format(url))
	# Pass original Referer for subsequent resource requests
	if flask.request.headers.get('referer'):
		headers = { "Referer" : flask.request.headers.get('referer')}
	else:
		headers = {}
	# Fetch the URL, and stream it back
	return requests.get(url, stream=True, params=request.args,
						headers=headers)
    

@app.route('/')
def index():
	""" Determine if user has credentials already,
		if not or they are expired, send to oauth2 workflow.
		
		Based on https://developers.google.com/api-client-library/python/auth/web-app
		"""
	if 'credentials' not in flask.session:
	    # Look for 
		flask.session['next'] = flask.request.args['next'] or \
		                        flask.request.headers.get('referer') or \
								flask.url_for('index')
		return flask.redirect(flask.url_for('oauth2callback'))
    
	""" We want to use environmental variables instead of a json file for 
        client secret information, so use OAuth2WebServerFlow instead of the
        `OAuth2Credentials.from_json` method found at:
        https://developers.google.com/api-client-library/python/guide/aaa_oauth#OAuth2WebServerFlow
    """
	credentials = client.OAuth2Credentials \
						.from_json(flask.session['credentials'])

  	if credentials.access_token_expired:
		return flask.redirect(flask.url_for('oauth2callback'))
  	else:
  	    return flask.redirect(flask.session['next'])


@app.route('/oauth2callback')
def oauth2callback():
	""" Send user to Google for authentication"""
	google_redirect_uri = "{}oauth2callback".format(flask.request.url_root)
	
	flow = client.OAuth2WebServerFlow(client_id=GOOGLE_CLIENT_ID,
									  client_secret=GOOGLE_SECRET,
									  scope=GOOGLE_SCOPE,
									  redirect_uri=google_redirect_uri)

	if 'code' not in flask.request.args:
		# Send user to Google for authentication code
		auth_uri = flow.step1_get_authorize_url()
		return flask.redirect(auth_uri)
	else:
		# Exchange an authorization code for a Credentials object
		auth_code = flask.request.args.get('code')
		credentials = flow.step2_exchange(auth_code)
		flask.session['credentials'] = credentials.to_json()
		return flask.redirect(flask.session['next'])


if __name__ == '__main__':
	import uuid
	app.secret_key = str(uuid.uuid4())
	app.debug = True
	app.run()
