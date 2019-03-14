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

r = redis.StrictRedis(host='localhost', port=6379, db=0)


class redis_info:
    """ This class is used to set , get and delete data from Redis cache """

    try:
        def token_set(self, key, value):
            if key and value:
                r.set(key, value)
            else:
                return HttpResponse("Invalid Credentials")

        def token_get(self, key):

            if key:
                value = r.get(key)
                return value
            else:
                return HttpResponse("Invalid Credentials")

        def flush_all(self):
            r.flushall(asynchronous=False)


    except Exception as e:
        print(e)

