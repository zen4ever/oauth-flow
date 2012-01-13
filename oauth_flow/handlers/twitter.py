from oauth_flow.handlers import ConsumerBasedOAuth


# Twitter configuration
TWITTER_SERVER = 'api.twitter.com'
TWITTER_REQUEST_TOKEN_URL = 'https://%s/oauth/request_token' % TWITTER_SERVER
TWITTER_ACCESS_TOKEN_URL = 'https://%s/oauth/access_token' % TWITTER_SERVER
# Note: oauth/authorize forces the user to authorize every time.
#       oauth/authenticate uses their previous selection, barring revocation.
TWITTER_AUTHORIZATION_URL = 'http://%s/oauth/authenticate' % TWITTER_SERVER


class TwitterHandler(ConsumerBasedOAuth):
    """Twitter OAuth authentication mechanism"""
    AUTHORIZATION_URL = TWITTER_AUTHORIZATION_URL
    REQUEST_TOKEN_URL = TWITTER_REQUEST_TOKEN_URL
    ACCESS_TOKEN_URL = TWITTER_ACCESS_TOKEN_URL
    SERVICE = 'twitter'
