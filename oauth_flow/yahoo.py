from oauth_flow.handlers import ConsumerBasedOAuth


class YahooAuth(ConsumerBasedOAuth):
    AUTHORIZATION_URL = 'https://api.login.yahoo.com/oauth/v2/request_auth'
    REQUEST_TOKEN_URL = 'https://api.login.yahoo.com/oauth/v2/get_request_token'
    ACCESS_TOKEN_URL = 'https://api.login.yahoo.com/oauth/v2/get_token'
    SERVER_URL = 'api.login.yahoo.com'

    SETTINGS_KEY_NAME = 'YAHOO_CONSUMER_KEY'
    SETTINGS_SECRET_NAME = 'YAHOO_CONSUMER_SECRET'
