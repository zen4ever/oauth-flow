import logging
logger = logging.getLogger(__name__)


import cgi
from urllib import urlencode
from urllib2 import urlopen

from django.conf import settings
from django.utils import simplejson
from django.contrib.auth import authenticate

from oauth_flow.handlers import BaseOAuth2


FACEBOOK_ME = 'https://graph.facebook.com/me?'


def sanitize_log_data(secret, data=None, leave_characters=4):
    """
    Clean private/secret data from log statements and other data.

    Assumes data and secret are strings. Replaces all but the first
    `leave_characters` of `secret`, as found in `data`, with '*'.

    If no data is given, all but the first `leave_characters` of secret
    are simply replaced and returned.
    """
    replace_secret = (secret[:leave_characters] +
                      (len(secret) - leave_characters) * '*')

    if data:
        return data.replace(secret, replace_secret)

    return replace_secret


class FacebookAuth(BaseOAuth2):
    """Facebook OAuth2 support"""
    RESPONSE_TYPE = None
    SCOPE_SEPARATOR = ','
    AUTHORIZATION_URL = 'https://www.facebook.com/dialog/oauth'
    SETTINGS_KEY_NAME = 'FACEBOOK_APP_ID'
    SETTINGS_SECRET_NAME = 'FACEBOOK_API_SECRET'

    def get_scope(self):
        return getattr(settings, 'FACEBOOK_SCOPE', [])

    def user_data(self, access_token):
        """Loads user data from service"""
        data = None
        url = FACEBOOK_ME + urlencode({'access_token': access_token})

        try:
            data = simplejson.load(urlopen(url))
            logger.debug('Found user data for token %s',
                         sanitize_log_data(access_token),
                         extra=dict(data=data))
        except ValueError:
            extra = {'access_token': sanitize_log_data(access_token)}
            logger.error('Could not load user data from Facebook.',
                         exc_info=True, extra=extra)
        return data

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

    @classmethod
    def enabled(cls):
        """Return backend enabled status by checking basic settings"""
        return all(hasattr(settings, name) for name in ('FACEBOOK_APP_ID',
                                                        'FACEBOOK_API_SECRET'))
