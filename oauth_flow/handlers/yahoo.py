from oauth_flow.handlers import ConsumerBasedOAuth


class YahooHandler(ConsumerBasedOAuth):
    AUTHORIZATION_URL = 'https://api.login.yahoo.com/oauth/v2/request_auth'
    REQUEST_TOKEN_URL = 'https://api.login.yahoo.com/oauth/v2/get_request_token'
    ACCESS_TOKEN_URL = 'https://api.login.yahoo.com/oauth/v2/get_token'
    SERVICE = 'yahoo'
