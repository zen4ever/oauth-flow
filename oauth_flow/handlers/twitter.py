from django.utils import simplejson as json

from oauth_flow.handlers import ConsumerBasedOAuth


# Twitter configuration
TWITTER_SERVER = 'api.twitter.com'
TWITTER_REQUEST_TOKEN_URL = 'https://%s/oauth/request_token' % TWITTER_SERVER
TWITTER_ACCESS_TOKEN_URL = 'https://%s/oauth/access_token' % TWITTER_SERVER
# Note: oauth/authorize forces the user to authorize every time.
#       oauth/authenticate uses their previous selection, barring revocation.
TWITTER_AUTHORIZATION_URL = 'http://%s/oauth/authenticate' % TWITTER_SERVER
TWITTER_CHECK_AUTH = 'https://twitter.com/account/verify_credentials.json'


class TwitterAuth(ConsumerBasedOAuth):
    """Twitter OAuth authentication mechanism"""
    AUTHORIZATION_URL = TWITTER_AUTHORIZATION_URL
    REQUEST_TOKEN_URL = TWITTER_REQUEST_TOKEN_URL
    ACCESS_TOKEN_URL = TWITTER_ACCESS_TOKEN_URL
    SERVER_URL = TWITTER_SERVER
    SETTINGS_KEY_NAME = 'TWITTER_CONSUMER_KEY'
    SETTINGS_SECRET_NAME = 'TWITTER_CONSUMER_SECRET'

    def user_data(self, access_token):
        """Return user data provided"""
        request = self.oauth_request(access_token, TWITTER_CHECK_AUTH)
        data = self.fetch_response(request)
        try:
            return json.loads(data)
        except ValueError:
            return None
