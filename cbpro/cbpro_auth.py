from requests.auth import AuthBase
from requests import Session
from time import time
import requests
import logging
import hashlib
import base64
import hmac


class AdvancedTradeAuth(AuthBase):

    def __init__(self, key, secret):

        self.key = key
        self.secret = secret

    def __call__(self, request):

        timestamp = int(time())
        message = str(timestamp) + request.method + \
                    request.path_url.split('?')[0] + \
                    str(request.body or '')

        signature = hmac.new(
                            self.secret.encode('utf-8'),
                            message.encode('utf-8'),
                            digestmod=hashlib.sha256
                            ).hexdigest()

        request.headers.update({
                                'Content-Type': 'Application/JSON',
                                'CB-ACCESS-KEY': self.key,
                                'CB-ACCESS-SIGN': signature,
                                'CB-ACCESS-TIMESTAMP': timestamp
                                })
        return request
