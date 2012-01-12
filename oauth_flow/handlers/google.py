from oauth_flow.handlers import BaseOAuth2

GOOGLE_OAUTH_SCOPE = ['https://www.googleapis.com/auth/userinfo#email']


class GoogleOAuth2(BaseOAuth2):
    """Google OAuth2 support"""
    AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/auth'
    ACCESS_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
    SERVICE = 'google'

    def get_scope(self):
        return GOOGLE_OAUTH_SCOPE + super(GoogleOAuth2, self).get_scope() 
