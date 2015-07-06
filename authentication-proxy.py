import json
import os

import flask
import httplib2

from oauth2client import client


GOOGLE_CLIENT_ID = os.getenv("Google_client_id", None)
GOOGLE_SECRET = os.getenv("Google_secret", None)
GOOGLE_SCOPE = os.getenv("Google_scope", None)


app = flask.Flask(__name__)


@app.route('/')
def index():
	""" Determine if user has credentials already,
		if not or they are expired, send to oauth2 workflow.
	"""
	if 'credentials' not in flask.session:
		flask.session['next'] = flask.request.args['next'] or \
								flask.url_for('index')
		return flask.redirect(flask.url_for('oauth2callback'))

	credentials = client.OAuth2Credentials \
						.from_json(flask.session['credentials'])

  	if credentials.access_token_expired:
		return flask.redirect(flask.url_for('oauth2callback'))
  	else:
		http_auth = credentials.authorize(httplib2.Http())
    	return http_auth


@app.route('/oauth2callback')
def oauth2callback():
	""" Send user to Google for authentication
	"""
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
