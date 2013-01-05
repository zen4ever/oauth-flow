from oauth_flow.handlers import BaseOAuth2

AOL_OAUTH_SCOPE = [
    'https://www.AOLapis.com/auth/userinfo.profile',
    'https://www.AOLapis.com/auth/userinfo.email',
]


class AOLHandler(BaseOAuth2):
    """AOL OAuth2 support"""
    AUTHORIZATION_URL = 'https://api.screenname.aol.com/auth/authorize'
    ACCESS_TOKEN_URL = 'https://api.screenname.aol.com/auth/access_token'
    SERVICE = 'aol'

    def get_scope(self):
        return AOL_OAUTH_SCOPE + super(AOLHandler, self).get_scope() 
