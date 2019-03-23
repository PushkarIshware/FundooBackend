"""
******************************************************************************
* Purpose:  Custom Decorator for validating JWT_token.
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   11-3-2018
*
******************************************************************************
"""
import os

import jwt
from django.contrib.auth.models import User
from rest_framework.exceptions import PermissionDenied

from .services import redis_methods


def custom_login_required(function):
    def wrap(request, *args, **kwargs):
        token = request.META.get('HTTP_AUTHORIZATION')

        token_decode = jwt.decode(token, os.getenv("SIGNATURE"), algorithms=['HS256'])

        uname = token_decode.get('username')

        user_id = User.objects.get(username=uname)

        entry = User.objects.get(pk=user_id.id)

        request.user_id = user_id

        redis_methods.set_token('token', token)
        print('logged in redis token----------------', redis_methods.get_token('token'))

        if entry:
            return function(request, *args, **kwargs)
        else:
            raise PermissionDenied

    return wrap
