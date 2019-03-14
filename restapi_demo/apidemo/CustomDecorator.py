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

import jwt
from django.contrib.auth.models import User
from rest_framework.exceptions import PermissionDenied


def custom_login_required(function):
    def wrap(request, *args, **kwargs):
        print(request.META.get('HTTP_AUTHORIZATION'))
        token = request.META.get('HTTP_AUTHORIZATION')
        print("---------------------------------------", token)

        token_decode = jwt.decode(token, "Cypher", algorithms=['HS256'])
        uname = token_decode.get('username')

        print("---------------------uname------------------", uname)
        user_id = User.objects.get(username=uname)

        print("-------user__id", user_id)
        entry = User.objects.get(pk=user_id.id)

        print("-----------------entry----------------------", entry)
        request.user_id = user_id

        if entry:
            return function(request, *args, **kwargs)
        else:
            raise PermissionDenied

    return wrap
