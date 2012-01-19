import logging
logger = logging.getLogger(__name__)


import cgi
from urllib import urlencode
from urllib2 import urlopen

from oauth_flow.handlers import BaseOAuth2, OAuth20Token


class FacebookHandler(BaseOAuth2):
    """Facebook OAuth2 support"""
    RESPONSE_TYPE = None
    SCOPE_SEPARATOR = ','
    AUTHORIZATION_URL = 'https://www.facebook.com/dialog/oauth'
    SERVICE = 'facebook'

    def get_access_token_from_response(self, response):
        expires = response.get('expires', [None])[0]
        return OAuth20Token(response['access_token'][0], expires)

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

            return self.get_access_token_from_response(response)
        else:
            error = self.data.get('error') or 'unknown error'
            raise ValueError('Authentication error: %s' % error)
