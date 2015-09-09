# -*- coding: utf-8 -*-
import base64
import requests
import string
import random
import urllib
import time
import hmac
import collections
from hashlib import sha1


class Twip():

    base_url = 'https://api.twitter.com'
    oauth_url = '%s/oauth2/token' % base_url
    mentions_url = '%s/1.1/statuses/mentions_timeline.json' % base_url

    def __init__(self, consumer_key, consumer_secret, access_token, access_token_secret):
        self.credentials = base64.b64encode(':'.join([consumer_key, consumer_secret]))
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.access_token = access_token
        self.access_token_secret = access_token_secret

    def build_url(self, url, **params):
        if params:
            url += '?'
            for key, value in params.iteritems():
                url += '%s=%s&' % (key, value)
            return url[:-1]
        else:
            return url

    def get_mentions(self, **params):
        url = self.build_url(self.mentions_url, **params)
        authorization = self.authorize(self.mentions_url, **params)
        headers = {'Authorization': authorization}
        return requests.get(url, headers=headers)

    def get_bearer_token(self):
        if hasattr(self, 'bearer_token'):
            return self.bearer_token
        else:
            headers = {
                'Authorization': 'Basic ' + self.credentials,
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
            }
            body = 'grant_type=client_credentials'
            r = requests.post(self.oauth_url, data=body, headers=headers)
            self.bearer_token = r.json().get('access_token', None)
            return self.bearer_token

    def authorize(self, url, **url_params):
        params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_nonce': self.get_random_string(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_token': self.access_token,
            'oauth_version': '1.0'
        }

        sign_params = params.copy()
        for param, param_value in url_params.iteritems():
            sign_params[param] = str(param_value)

        ordered_params = collections.OrderedDict(sorted(sign_params.items()))
        oauth_signature = self.create_signature('get', url, ordered_params)
        params['oauth_signature'] = oauth_signature

        header_string = 'OAuth '
        for key, val in params.iteritems():
            key_value = (urllib.quote(key, safe=''), urllib.quote(val, safe=''),)
            header_string += '%s="%s", ' % key_value
        return header_string[:-2]

    def get_random_string(self):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for i in range(10))

    def create_signature(self, method, url, params):
        param_string = ''
        for key, val in params.iteritems():
            key_value = (urllib.quote(key, safe=''), urllib.quote(val, safe=''),)
            param_string += '%s=%s&' % (key_value)
        param_string = param_string[:-1]

        base_string = method.upper() + '&'
        base_string += urllib.quote(url, safe='') + '&'
        base_string += urllib.quote(param_string, safe='')
        print base_string

        secrets = [self.consumer_secret, self.access_token_secret]
        signing_key = '&'.join([urllib.quote(s, safe='') for s in secrets])
        hashed = hmac.new(signing_key, base_string, sha1)
        return hashed.digest().encode('base64').rstrip('\n')
