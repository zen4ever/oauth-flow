import logging
logger = logging.getLogger(__name__)


import cgi
from urllib import urlencode
from urllib2 import urlopen

from oauth_flow.handlers import BaseOAuth2


class FacebookAuth(BaseOAuth2):
    """Facebook OAuth2 support"""
    RESPONSE_TYPE = None
    SCOPE_SEPARATOR = ','
    AUTHORIZATION_URL = 'https://www.facebook.com/dialog/oauth'
    SERVICE = 'facebook'

    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        if 'code' in self.data:
            key, secret = self.get_key_and_secret()
            url = 'https://graph.facebook.com/oauth/access_token?' + \
                  urlencode({'client_id': key,
                             'redirect_uri': self.redirect_uri,
                             'client_secret': secret,
                             'code': self.data['code']})
            response = cgi.parse_qs(urlopen(url).read())
            access_token = response['access_token'][0]
            return access_token
        else:
            error = self.data.get('error') or 'unknown error'
            raise ValueError('Authentication error: %s' % error)
