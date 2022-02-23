# -*- coding: utf-8 -*-
import json
import os
import urllib.parse
from typing import Dict
import flask
import requests
from requests.auth import HTTPBasicAuth

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

with open(CLIENT_SECRETS_FILE, "r", encoding='UTF-8') as f:
    secrets = json.loads(f.read())
    CLIENT_ID = secrets["web"]["client_id"]
    CLIENT_SECRET = secrets["web"]["client_secret"]

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['email', 'openid',
          'https://www.googleapis.com/auth/drive.readonly',
          'https://www.googleapis.com/auth/youtube.readonly']

app = flask.Flask(__name__)

# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'REPLACE ME - this value is here as a placeholder.'


@app.route('/')
def index():
    return print_index_table()


@app.route('/test')
def test_api_request():
    if 'token' not in flask.session:
        return flask.redirect('login')

    token = flask.session['token']

    # Get ALL the subscriptions from ALL the pages from the current user
    # 'https://youtube.googleapis.com/youtube/v3/subscriptions?part=snippet&mine=true&maxResults=50&alt=json'
    # request = youtube.subscriptions().list(part="snippet", mine=True, maxResults=50)
    # response = request.execute()
    response = requests.get(
        url='https://youtube.googleapis.com/youtube/v3/subscriptions',
        params={
            'part': 'snippet',
            'mine': 'true',
            'maxResults': '50',
            'alt': 'json'
        },
        headers={'content-type': 'application/json', 'Authorization': f'Bearer {token}'},
    )
    items = response.json().get('items', [])

    # Get the next page of results if there is one
    while 'nextPageToken' in response.json():
        page_token = response.json()['nextPageToken']
        response = requests.get(
            url='https://youtube.googleapis.com/youtube/v3/subscriptions',
            params={
                'part': 'snippet',
                'mine': 'true',
                'maxResults': '50',
                'alt': 'json',
                'pageToken': page_token
            },
            headers={'content-type': 'application/json', 'Authorization': f'Bearer {token}'},
        )
        items = items + response.json().get('items', [])

    # List the name of the subscriptions
    subscriptions = [item['snippet']['title'] for item in items]

    return flask.jsonify({"titles": subscriptions})


@app.route('/login')
def login():
    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    google_oauth_url = "https://accounts.google.com/o/oauth2/auth"
    query_params: Dict[str, str] = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": "http://localhost:9000/auth",
        "scope": " ".join(SCOPES),
        "state": "ETL04Oop9e1yFQQFRM2KpHvbWwtMRV",
        "access_type": "offline",
        "include_granted_scopes": "true"
    }
    authorization_url = f"{google_oauth_url}?{urllib.parse.urlencode(query_params)}"
    return flask.redirect(authorization_url)


@app.route('/auth')
def auth():
    # Parse query parameters to dictionary
    params = flask.request.args.to_dict()

    token_response = requests.post('https://oauth2.googleapis.com/token',
                                   auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
                                   params={
                                       'grant_type': "authorization_code",
                                       "code": params["code"],
                                       "redirect_uri": "http://localhost:9000/auth"
                                   },
                                   headers={'content-type': 'application/json'})

    print(token_response.json().get('refresh_token', 'No refresh token'))
    flask.session['token'] = token_response.json()['access_token']

    return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/login">login</a> before ' +
                'testing the code to revoke credentials.')

    token = flask.session['token']

    revoke_response = requests.post('https://oauth2.googleapis.com/revoke',
                                    params={'token': token},
                                    headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke_response, 'status_code')
    if status_code == 200:
        return 'Credentials successfully revoked.' + print_index_table()
    return 'An error occurred.' + print_index_table()


@app.route('/clear')
def clear_credentials():
    if 'token' in flask.session:
        del flask.session['token']
    return ('Credentials have been cleared.<br><br>' +
            print_index_table())


def print_index_table():
    return ('<table>' +
            '<tr><td><a href="/test">Test an API request</a></td>' +
            '<td>Submit an API request and see a formatted JSON response. ' +
            '    Go through the authorization flow if there are no stored ' +
            '    credentials for the user.</td></tr>' +
            '<tr><td><a href="/login">Test the auth flow directly</a></td>' +
            '<td>Go directly to the authorization flow. If there are stored ' +
            '    credentials, you still might not be prompted to reauthorize ' +
            '    the application.</td></tr>' +
            '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
            '<td>Revoke the access token associated with the current user ' +
            '    session. After revoking credentials, if you go to the test ' +
            '    page, you should see an <code>invalid_grant</code> error.' +
            '</td></tr>' +
            '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
            '<td>Clear the access token currently stored in the user session. ' +
            '    After clearing the token, if you <a href="/test">test the ' +
            '    API request</a> again, you should go back to the auth flow.' +
            '</td></tr></table>')


if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run('localhost', 9000, debug=True)
