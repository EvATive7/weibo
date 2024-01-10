# -*- coding: utf-8 -*-

"""
Python sina weibo sdk developed by github@lxyu. (https://github.com/lxyu/weibo)
Forked by EvATive7. (https://github.com/EvATive7/weibo)
"""

from urllib.parse import urlencode

import json
import time

import requests


class Client(object):
    # const define
    _host = 'https://api.weibo.com/'
    _authorization_url = _host + 'oauth2/authorize'
    _token_url = _host + 'oauth2/access_token'
    _api_url = _host + '2/'

    def __init__(self, api_key, api_secret, redirect_uri,
                 token=None,
                 username=None, password=None,
                 #TODO:try_to_auth=False
                 ):

        # init basic info
        self.client_id = api_key
        self.client_secret = api_secret
        self.redirect_uri = redirect_uri

        self._session = requests.session()

        if username and password:
            self._session.auth = username, password
        elif token:
            self.auth_by_token(token)
        #elif try_to_auth:
        #    pass

    @property
    def client_authorize_url(self):
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri
        }
        return "{0}?{1}".format(self._authorization_url, urlencode(params))

    @property
    def alive(self):
        if self.expires_at:
            return self.expires_at > time.time()
        else:
            return False

    # def auto_auth(self):
    #
    #    pass

    def auth_by_code(self, authorization_code):
        """Activate client by authorization_code.
        """
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'code': authorization_code,
            'redirect_uri': self.redirect_uri
        }
        res = requests.post(self._token_url, data=params)
        token = json.loads(res.text)
        self._assert_error(token)

        token[u'expires_at'] = int(time.time()) + int(token.pop(u'expires_in'))
        self.auth_by_token(token)

    def auth_by_token(self, token):
        """Directly activate client by access_token.
        """
        self.token = token

        self.uid = token['uid']
        self.access_token = token['access_token']
        self.expires_at = token['expires_at']

        self._session.params = {'access_token': self.access_token}

    def _assert_error(self, d):
        """Assert if json response is error.
        """
        if 'error_code' in d and 'error' in d:
            raise RuntimeError("{0} {1}".format(
                d.get("error_code", ""), d.get("error", "")))

    def get(self, uri, **kwargs):
        """Request resource by get method.
        """
        url = "{0}{1}.json".format(self._api_url, uri)

        # for username/password client auth
        if self._session.auth:
            kwargs['source'] = self.client_id

        res = json.loads(self._session.get(url, params=kwargs).text)
        self._assert_error(res)
        return res

    def post(self, uri, **kwargs):
        """Request resource by post method.
        """
        url = "{0}{1}.json".format(self._api_url, uri)

        # for username/password client auth
        if self._session.auth:
            kwargs['source'] = self.client_id

        if "pic" not in kwargs:
            res = json.loads(self._session.post(url, data=kwargs).text)
        else:
            files = {"pic": kwargs.pop("pic")}
            res = json.loads(self._session.post(url,
                                                data=kwargs,
                                                files=files).text)
        self._assert_error(res)
        return res
