# import jwt
# from django.contrib.auth.models import User
# from rest_framework import HTTP_HEADER_ENCODING
# from rest_framework.exceptions import PermissionDenied
# from django.http import request
#
# import jwt
#
#
# def custom_login_required(function):
#     def wrap(request, *args, **kwargs):
#         uid = request.META.get('HTTP_AUTHORIZATION')
#         print(uid)
#         userdata = jwt.decode(uid, "Cypher", algorithm='HS256')
#         uname = userdata['username']
#         valid = User.objects.get(username=uname)
#         if valid:
#             return function(request, *args, **kwargs)
#         else:
#             raise PermissionDenied
#
#
# # def jwt_tok(request):
# #     uid = request.META.get('HTTP_AUTHORIZATION')
# #     print('from a header---------------------------', uid)
# #     print("uid -s ---", uid)
# #     userdata = jwt.decode(uid, "Cypher", algorithm='HS256')
# #     # uid = userdata['user_id']
# #     uname = userdata['username']
# #     valid = User.objects.get(username=uname)
# #     print(valid, "validation given tokennnnnnnnnnnnnnnnnnnnnnnn")
# #     if valid:
# #         return (request, uname)
# #     else:
# #         return "invalid entry"
