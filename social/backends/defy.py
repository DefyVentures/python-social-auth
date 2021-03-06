from base64 import b64encode
import re
import socket

from social.backends import oauth


class DefyVenturesOAuth2Backend(oauth.BaseOAuth2):
    """Defy Ventures OAuth authentication backend"""

    name = 'defyventures'

    AUTHORIZATION_PATH = '/oauth2/authorize/'
    ACCESS_TOKEN_PATH  = '/oauth2/token/'
    USER_DATA_PATH     = '/api/user'

    SETTING_PREFIX = 'SOCIAL_AUTH_DEFYVENTURES_OAUTH2_'
    ACCESS_TOKEN_METHOD = 'POST'
    EXTRA_DATA = [
        ('id', 'id'),
        ('expires', 'expires')
    ]

    def defy_setting(self, name, default=None):
        """Return setting value from strategy"""
        name = self.SETTING_PREFIX + name
        return self.strategy.setting(name, default=default, backend=self)

    def get_base_url(self):
        return self.defy_setting('BASE_URL', 'http://learn.defyventures.org')

    def authorization_url(self):
        return self.get_base_url() + self.AUTHORIZATION_PATH

    def access_token_url(self):
        return self.get_base_url() + self.ACCESS_TOKEN_PATH

    def get_user_details(self, response):
        """Return user details from Defy Ventures account"""
        email = response.get('email')
        username = email.replace('@', 'AT')
        username = re.sub('[^a-zA-Z0-9]', '', username)
        first_name = response.get('first_name', '')
        last_name = response.get('last_name', '')
        full_name = first_name + ' ' + last_name
        full_name = full_name.strip()
        details = {
            'username': username,
            'email': email,
            'fullname': full_name,
        }
        return details

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = self.get_base_url() + self.USER_DATA_PATH
        return self.get_json(url, params={'token': access_token})

    def auth_params(self, state=None):
        client_id = self.defy_setting('KEY')
        params = {
            'client_id': client_id,
            'redirect_uri': self.get_redirect_uri(state),
        }
        if self.STATE_PARAMETER and state:
            params['state'] = state
        if self.RESPONSE_TYPE:
            params['response_type'] = self.RESPONSE_TYPE
        return params


    def get_redirect_uri(self, state=None):
        """Return redirect without redirect_state parameter."""
        return self.redirect_uri

    def auth_headers(self):
        client_auth = b64encode(self.defy_setting('KEY') + ':' + self.defy_setting('SECRET'))
        return {'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'Authorization': 'Basic {0}'.format(client_auth)}

