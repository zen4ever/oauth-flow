import httplib2
import json
import sys
from urllib2 import Request, urlopen
from urllib import urlencode

from oauth2 import Consumer as OAuthConsumer, Token, Request as OAuthRequest, \
                   SignatureMethod_HMAC_SHA1, Client

from oauth_flow.utils.anytree import etree


HANDLERS = (
    ('facebook', 'oauth_flow.handlers.facebook.FacebookHandler'),
    ('google', 'oauth_flow.handlers.google.GoogleHandler'),
    ('twitter', 'oauth_flow.handlers.twitter.TwitterHandler'),
    ('yahoo', 'oauth_flow.handlers.yahoo.YahooHandler'),
    ('aol', 'oauth_flow.handlers.aol.AOLHandler'),
)


def import_module(name):
    """
    Simplified version of import_module from Django,
    supports only absolute imports.
    """
    __import__(name)
    return sys.modules[name]


class ImproperlyConfigured(Exception):
    pass


class NotAuthorized(Exception):
    pass


class ServiceFail(Exception):
    pass


class OAuth20Token(object):

    def __init__(self, token, expires=None):
        self.token = token
        if expires is not None:
            import datetime
            self.expires = datetime.datetime.now() + datetime.timedelta(seconds=int(expires))
        else:
            self.expires = None

    def __str__(self):
        return str(self.token)


def get_handler(service, **kwargs):
    handlers = kwargs.get('handlers', HANDLERS)
    # exctract settings for individual service
    settings = kwargs.pop('settings', {}).get(service, {})
    handler_module = dict(handlers).get(service, None)
    if handler_module:
        module, handler = handler_module.rsplit('.', 1)
        handler_class = getattr(import_module(module), handler)
        handler_instance = handler_class(settings=settings, **kwargs)
        return handler_instance
    raise ImproperlyConfigured('No handler for service %s' % service)


class BaseOAuth(object):

    def __init__(self, request=None, redirect=None, redirect_uri=None, **kwargs):
        """Init method"""
        self.request = request
        if request:
            self.data = request.REQUEST
        self.redirect = redirect
        self.redirect_uri = redirect_uri
        if redirect and request:
            self.redirect_uri = request.build_absolute_uri(redirect)
        self.settings = kwargs.get('settings', {})

    def _process_response(self, kind, response, content):
        if response["status"] == "401":
            raise NotAuthorized()
        if not content:
            raise ServiceFail("no content")
        if kind == "raw":
            return content
        elif kind == "json":
            return json.loads(content)
        elif kind == "xml":
            return etree.ElementTree(etree.fromstring(content))
        else:
            raise Exception("unsupported API kind")

    def get_user_id(self, response):
        return response['id']

    def auth_extra_arguments(self):
        return self.settings.get('EXTRA_ARGUMENTS', {})

    def get_key_and_secret(self):
        """Return tuple with Consumer Key and Consumer Secret for current
        service provider. Must return (key, secret), order *must* be respected.
        """
        return self.settings['KEY'], self.settings['SECRET']

    def get_scope(self):
        """Return list with needed access scope"""
        return self.settings.get('SCOPE', [])


class ConsumerBasedOAuth(BaseOAuth):
    """Consumer based mechanism OAuth authentication, fill the needed
    parameters to communicate properly with authentication service.

        @AUTHORIZATION_URL       Authorization service url
        @REQUEST_TOKEN_URL       Request token URL
        @ACCESS_TOKEN_URL        Access token URL
    """
    AUTHORIZATION_URL = ''
    REQUEST_TOKEN_URL = ''
    ACCESS_TOKEN_URL = ''

    @property
    def unauthorized_token_name(self):
        return self.SERVICE + '_unauthorized_token_name'

    def auth_url(self):
        """Return redirect url"""
        token = self.unauthorized_token()
        self.request.session[self.unauthorized_token_name] = token.to_string()
        return self.oauth_authorization_request(token).to_url()

    def auth_complete(self, *args, **kwargs):
        """Return user, might be logged in"""
        unauthed_token = self.request.session.get(self.unauthorized_token_name)
        if not unauthed_token:
            raise ValueError('Missing unauthorized token')

        token = Token.from_string(unauthed_token)
        if token.key != self.data.get('oauth_token', 'no-token'):
            raise ValueError('Incorrect tokens')

        access_token = self.access_token(token)

        return access_token.to_string()

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

    @property
    def consumer(self):
        """Setups consumer"""
        return OAuthConsumer(*self.get_key_and_secret())

    def make_api_call(self, kind, url, token, method="GET", **kwargs):
        if isinstance(token, basestring):
            token = Token.from_string(token)
        client = Client(self.consumer, token=token)
        request_kwargs = dict(method=method)
        if method == "POST":
            request_kwargs["body"] = urlencode(kwargs["params"])
        response, content = client.request(url, **request_kwargs)
        return self._process_response(kind, response, content)


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

    def oauth_request(self, token, url, extra_params=None):
        params = {'access_token': token}
        if extra_params:
            params.update(extra_params)
        url = url + '?' + urlencode(params)
        data = json.load(urlopen(url))
        return data

    def get_access_token_from_response(self, response):
        return OAuth20Token(response['access_token'], response['expires_in'])

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
            return self.get_access_token_from_response(response)

    def make_api_call(self, kind, url, token, method="GET", **kwargs):
        request_kwargs = dict(method=method)
        if method == "POST":
            params = {
                "access_token": str(token),
            }
            params.update(kwargs["params"])
            request_kwargs["body"] = urlencode(params)
        else:
            symbol = "?"
            if "?" in url:
                symbol = "&"
            url += "%s%s" % (symbol, urlencode(dict(access_token=str(token))))
        http = httplib2.Http()
        response, content = http.request(url, **request_kwargs)
        return self._process_response(kind, response, content)
