import jwt
from django.contrib.auth.models import User
from rest_framework.exceptions import PermissionDenied


class jwtAUTH():
    def jwt_auth(function):
        def wrap(request, *args, **kwargs):
            print(request.META.get('HTTP_AUTHORIZATION'))
            token = request.META.get('HTTP_AUTHORIZATION')
            token_split = token.split(' ')
            token_get = token_split[1]
            print("My Token:", token_get)

            token_decode = jwt.decode(token_get, "secret_key", algorithms=['HS256'])
            eid = token_decode.get('email')
            user_id = User.object.get(email=eid)
            print("Email", eid)
            print("User id", user_id.id)
            entry = User.object.get(pk=user_id.id)
            print(entry)
            if entry:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied