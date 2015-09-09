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

    oauth_url = 'https://api.twitter.com/oauth2/token'
    mentions_url = 'https://api.twitter.com/1.1/statuses/mentions_timeline.json'

    def __init__(self, consumer_key, consumer_secret, access_token, access_token_secret):
        self.credentials = base64.b64encode(':'.join([consumer_key, consumer_secret]))
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.access_token = access_token
        self.access_token_secret = access_token_secret

    def get_mentions(self):
        headers = {'Authorization': self.authorize(self.mentions_url)}
        return requests.get(self.mentions_url, headers=headers)

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

    def authorize(self, url):
        params = {
            'oauth_consumer_key': self.consumer_key,
            'oauth_nonce': self.get_random_string(),
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': str(int(time.time())),
            'oauth_token': self.access_token,
            'oauth_version': '1.0'
        }

        ordered_params = collections.OrderedDict(sorted(params.items()))

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

        signing_key = urllib.quote(self.consumer_secret, safe='') + '&' + urllib.quote(self.access_token_secret, safe='')
        hashed = hmac.new(signing_key, base_string, sha1)
        return hashed.digest().encode('base64').rstrip('\n')
