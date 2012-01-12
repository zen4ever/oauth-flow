import logging
logger = logging.getLogger(__name__)


import cgi
from urllib import urlencode
from urllib2 import urlopen

from django.conf import settings
from django.contrib.auth import authenticate

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
            url = 'https://graph.facebook.com/oauth/access_token?' + \
                  urlencode({'client_id': settings.FACEBOOK_APP_ID,
                             'redirect_uri': self.redirect_uri,
                             'client_secret': settings.FACEBOOK_API_SECRET,
                             'code': self.data['code']})
            response = cgi.parse_qs(urlopen(url).read())
            access_token = response['access_token'][0]
            data = self.user_data(access_token)
            if data is not None:
                if 'error' in data:
                    error = self.data.get('error') or 'unknown error'
                    raise ValueError('Authentication error: %s' % error)
                data['access_token'] = access_token
                # expires will not be part of response if offline access
                # premission was requested
                if 'expires' in response:
                    data['expires'] = response['expires'][0]
            kwargs.update({'response': data, self.AUTH_BACKEND.name: True})
            return authenticate(*args, **kwargs)
        else:
            error = self.data.get('error') or 'unknown error'
            raise ValueError('Authentication error: %s' % error)
