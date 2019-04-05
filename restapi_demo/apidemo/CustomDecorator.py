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
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
from .services import redis_methods


def custom_login_required(function):
    def wrap(request, *args, **kwargs):
        token = request.META.get('HTTP_AUTHORIZATION')  # get token from LocalStorage

        token_decode = jwt.decode(token, os.getenv("SIGNATURE"), algorithms=['HS256'])  # decode given token

        username = token_decode.get('username')  # retrieve username from token

        user_id = User.objects.get(username=username)  # get user_id from username

        is_present = User.objects.get(pk=user_id.id)  # search to database using user_id

        request.user_id = user_id

        # redis_methods.set_token('token', token)

        if is_present:  # if present then go to next step
            return function(request, *args, **kwargs)
        else:
            raise PermissionDenied  # show invalid user entry

    return wrap
