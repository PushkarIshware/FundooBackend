"""
******************************************************************************
* Purpose:  Service File for S3 and Redis Cache.
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   14-3-2018
*
******************************************************************************
"""

import redis
from django.http import HttpResponse

import redis

r = redis.StrictRedis(host='localhost', port=6379, db=0)


class redis_methods:

    def set_token(key, value):
        r.set(key, value)
        print('token set')

    def get_token(key):
        token = r.get(key)
        return token
