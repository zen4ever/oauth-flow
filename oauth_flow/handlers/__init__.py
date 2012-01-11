from urllib2 import Request, urlopen
from urllib import urlencode

from django.conf import settings
from django.utils import simplejson as json

from django.contrib.auth import authenticate

from oauth2 import Consumer as OAuthConsumer, Token, Request as OAuthRequest, \
                   SignatureMethod_HMAC_SHA1


HANDLERS = {
    ('facebook', 'oauth_flow.handlers.FacebookHandler'),
    ('google', 'oauth_flow.handlers.GoogleHandler'),
    ('twitter', 'oauth_flow.handlers.TwitterHandler'),
    ('yahoo', 'oauth_flow.handlers.YahooHandler'),
}

def get_handler(service, request, redirect):
    handlers = getattr(settings, 'OAUTH_FLOW_HANDLERS', HANDLERS)
    handler_module = dict(handlers).get(service, None)
    if handler_module:
        module, handler = handler_module.rsplit('.', 1)
        handler_class = getattr(import_module(module), handler)
        handler_instance = handler_class(request, redirect)
        return handler_instance
    raise ImproperlyConfigured('No handler for service %s' % service)

class BaseOAuth(object):

    def __init__(self, request, redirect):
        """Init method"""
        self.request = request
        self.data = request.REQUEST
        self.redirect = redirect
        self.redirect_uri = request.build_absolute_uri(redirect)

    def get_user_id(self, response):
        return response['id']


class ConsumerBasedOAuth(BaseOAuth):
    """Consumer based mechanism OAuth authentication, fill the needed
    parameters to communicate properly with authentication service.

        @AUTHORIZATION_URL       Authorization service url
        @REQUEST_TOKEN_URL       Request token URL
        @ACCESS_TOKEN_URL        Access token URL
        @SERVER_URL              Authorization server URL
    """
    AUTHORIZATION_URL = ''
    REQUEST_TOKEN_URL = ''
    ACCESS_TOKEN_URL = ''
    SERVER_URL = ''
    SETTINGS_KEY_NAME = ''
    SETTINGS_SECRET_NAME = ''

    def auth_url(self):
        """Return redirect url"""
        token = self.unauthorized_token()
        name = self.AUTH_BACKEND.name + 'unauthorized_token_name'
        self.request.session[name] = token.to_string()
        return self.oauth_authorization_request(token).to_url()

    def auth_complete(self, *args, **kwargs):
        """Return user, might be logged in"""
        name = self.AUTH_BACKEND.name + 'unauthorized_token_name'
        unauthed_token = self.request.session.get(name)
        if not unauthed_token:
            raise ValueError('Missing unauthorized token')

        token = Token.from_string(unauthed_token)
        if token.key != self.data.get('oauth_token', 'no-token'):
            raise ValueError('Incorrect tokens')

        access_token = self.access_token(token)
        data = self.user_data(access_token)
        if data is not None:
            data['access_token'] = access_token.to_string()

        kwargs.update({'response': data, self.AUTH_BACKEND.name: True})
        return authenticate(*args, **kwargs)

    def unauthorized_token(self):
        """Return request for unauthorized token (first stage)"""
        request = self.oauth_request(token=None, url=self.REQUEST_TOKEN_URL)
        response = self.fetch_response(request)
        return Token.from_string(response)

    def oauth_authorization_request(self, token):
        """Generate OAuth request to authorize token."""
        return self.oauth_request(token, self.AUTHORIZATION_URL,
                                  self.auth_extra_arguments())

    def oauth_request(self, token, url, extra_params=None):
        """Generate OAuth request, setups callback url"""
        params = {'oauth_callback': self.redirect_uri}
        if extra_params:
            params.update(extra_params)

        if 'oauth_verifier' in self.data:
            params['oauth_verifier'] = self.data['oauth_verifier']
        request = OAuthRequest.from_consumer_and_token(self.consumer,
                                                       token=token,
                                                       http_url=url,
                                                       parameters=params)
        request.sign_request(SignatureMethod_HMAC_SHA1(), self.consumer, token)
        return request

    def fetch_response(self, request):
        """Executes request and fetchs service response"""
        response = urlopen(request.to_url())
        return '\n'.join(response.readlines())

    def access_token(self, token):
        """Return request for access token value"""
        request = self.oauth_request(token, self.ACCESS_TOKEN_URL)
        return Token.from_string(self.fetch_response(request))

    def user_data(self, access_token):
        """Loads user data from service"""
        raise NotImplementedError('Implement in subclass')

    @property
    def consumer(self):
        """Setups consumer"""
        return OAuthConsumer(*self.get_key_and_secret())

    def get_key_and_secret(self):
        """Return tuple with Consumer Key and Consumer Secret for current
        service provider. Must return (key, secret), order *must* be respected.
        """
        return getattr(settings, self.SETTINGS_KEY_NAME, None), \
               getattr(settings, self.SETTINGS_SECRET_NAME, None)

    @classmethod
    def enabled(cls):
        """Return backend enabled status by checking basic settings"""
        return all(hasattr(settings, name) for name in
                        (cls.SETTINGS_KEY_NAME, cls.SETTINGS_SECRET_NAME))


class BaseOAuth2(BaseOAuth):
    AUTHORIZATION_URL = None
    ACCESS_TOKEN_URL = None
    SCOPE_SEPARATOR = ' '
    RESPONSE_TYPE = 'code'

    def auth_url(self):
        """Return redirect url"""
        client_id, client_secret = self.get_key_and_secret()
        args = {'client_id': client_id, 'redirect_uri': self.redirect_uri}

        scope = self.get_scope()
        if scope:
            args['scope'] = self.SCOPE_SEPARATOR.join(self.get_scope())
        if self.RESPONSE_TYPE:
            args['response_type'] = self.RESPONSE_TYPE

        args.update(self.auth_extra_arguments())
        return self.AUTHORIZATION_URL + '?' + urlencode(args)

    def auth_complete(self, *args, **kwargs):
        """Completes loging process, must return user instance"""
        if self.data.get('error'):
            error = self.data.get('error_description') or self.data['error']
            raise ValueError('OAuth2 authentication failed: %s' % error)

        client_id, client_secret = self.get_key_and_secret()
        params = {'grant_type': 'authorization_code',  # request auth code
                  'code': self.data.get('code', ''),  # server response code
                  'client_id': client_id,
                  'client_secret': client_secret,
                  'redirect_uri': self.redirect_uri}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        request = Request(self.ACCESS_TOKEN_URL, data=urlencode(params),
                          headers=headers)

        try:
            response = json.loads(urlopen(request).read())
        except (ValueError, KeyError):
            raise ValueError('Unknown OAuth2 response type')

        if response.get('error'):
            error = response.get('error_description') or response.get('error')
            raise ValueError('OAuth2 authentication failed: %s' % error)
        else:
            response.update(self.user_data(response['access_token']) or {})
            kwargs.update({'response': response, self.AUTH_BACKEND.name: True})
            return authenticate(*args, **kwargs)

    def get_scope(self):
        """Return list with needed access scope"""
        return []

    def get_key_and_secret(self):
        """Return tuple with Consumer Key and Consumer Secret for current
        service provider. Must return (key, secret), order *must* be respected.
        """
        return getattr(settings, self.SETTINGS_KEY_NAME, None), \
               getattr(settings, self.SETTINGS_SECRET_NAME, None)