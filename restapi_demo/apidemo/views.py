from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, HTTP_HEADER_ENCODING
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .CustomDecorator import jwt, jwtAUTH
from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.contrib.auth import get_user_model, authenticate, login
import jwt
import json
from django.contrib.auth.models import User
import re
from django.http import JsonResponse
from PIL import Image
import boto3
from .serializers import registrationSerializer, LoginSerializer, NoteSerializer
from .models import Note
from django.views import View
from .models import Note



User = get_user_model()

'''
this is email activation method for checking given email is valid or not.
'''


def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)  # gets the username
        print('above if', user)
        if user and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            json_data = {
                "success": True,
                "message": "Successfully registered Go to login page"
            }
            return HttpResponse(json_data)
        else:
            return HttpResponse('Activation link is invalid!')
    except(TypeError, ValueError, User.DoesNotExist):
        return HttpResponse('Something bad happened')


class RestRegistration(CreateAPIView):
    """
        Registration API
    """

    serializer_class = registrationSerializer

    def post(self, request, *args, **kwargs):
        res = {"message": "something bad happened",
               "data": {},
               "success": False}
        print(request.data)
        username = request.data['username']
        email = request.data['email']
        password = request.data['password1']
        if username and email and password is not "":
            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_active = False
            user.save()

            message = render_to_string('acc_active_email.html', {
                'user': user,
                'domain': 'http://127.0.0.1:8000',
                # 'domain': 'http://127.0.0.1:4200',
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                'token': account_activation_token.make_token(user),
            })
            mail_subject = 'Activate your account...'
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            res['message'] = "registered Successfully...Please activate your Account"
            res['success'] = True
            return Response(res)
        else:
            return Response(res)


from rest_framework.authtoken.models import Token


# @require_POST
class RestLogin(CreateAPIView):
    """ Login API """

    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        res = {"message": "something bad happened",
               "data": {},
               "success": False,
               "user_id": {}}
        print(request.data)
        try:
            username = request.data['username']
            if username is None:
                raise Exception("Username is required")
            password = request.data['password']
            if password is None:
                raise Exception("password is required")
            user = authenticate(username=username, password=password)
            print('user-->', user)

            if user:
                if user.is_active:
                    login(request, user)
                    user_id = request.user
                    payload = {'username': username, 'password': password, "user_id": user_id.id}
                    # token = jwt.encode(payload, "secret_key", algorithm='HS256').decode('utf-8')
                    jwt_token = {
                        'token': jwt.encode(payload, "Cypher", algorithm='HS256').decode('utf-8')
                    }
                    print(jwt_token)
                    token = jwt_token['token']
                    res['message'] = "Logged in Successfully"
                    res['data'] = {"token": token, "username": username, "user_id": user_id.id}
                    res['success'] = True

                    return Response(res)
                else:
                    return Response(res)
            if user is None:
                return Response(res)
        except Exception as e:
            print(e)
            return Response(res)


@csrf_exempt
def UploadImg(request):
    if request.method == "POST":
        # username = "demo123"
        username = request.POST.get('name')
        print("---------------------------------", username)
        photo = request.FILES['profile']

        print(type(photo))
        # img = request.FILES['pic']
        image = Image.open(photo, 'r')
        # image.show()

        s3 = boto3.client('s3')
        username = str(username) + ".png"
        # s3 = boto3.resource('s3')
        # s3.Bucket('fundooapp').put_object(Body=image, Key=username)
        # s3.upload_fileobj(image, 'fundooapp', Key=username)
        # s3.put_object(Key=username, Body=image)
        s3.upload_fileobj(photo, 'fundooapp', username)
        print("file uploaded")
        return JsonResponse({"msg": "recieved at django"})

    else:
        return render(request, 'profile.html', {})


class AddNote(CreateAPIView):
    """Add Notes API"""

    serializer_class = NoteSerializer

    # @login_required
    # @jwt_auth(uid)
    def post(self, request, *args, **kwargs):
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }

            header_token = request.META['HTTP_AUTHORIZATION']
            userdata = jwt.decode(header_token, "Cypher", algorithm='HS256')
            uid = userdata['user_id']

            if uid is None:
                print("uid is none please login....note adding failed")
            serializer = NoteSerializer(data=request.data)

            if request.data['title'] and request.data['description'] is None:
                raise Exception("title and description required ")

            if serializer.is_valid():
                # serializer.user_id = uid
                serializer.save(user_id=uid)
                res['message'] = "note added"
                res['success'] = True
                return Response(res)
            return Response(res)
        except Exception as e:
            print(res, e)


# from django.core.serializers import serialize


class ShowNotes(View):
    """Show notes API"""

    def get(self, request):
        global note_data

        '''
        print('-------',request.META['HTTP_AUTHORIZATION'])
        uid=request.META['HTTP_AUTHORIZATION']
        '''

        uid = request.META['HTTP_AUTHORIZATION']
        print(type(uid))
        print("uid -s ---", uid)
        userdata = jwt.decode(uid, "Cypher", algorithm='HS256')
        uid = userdata['user_id']
        uname=userdata['username']
        print("-------------from token------ ",userdata['username'])
        res = {
            'message': 'Something bad happened',
            'data': {},
            'success': False
        }
        try:
                                            # user_id=uid
            uID=User.objects.get(username=uname).pk
            print("user id from username-------",uID)
            note_data = Note.objects.filter(user_id=uid).values('id', 'title', 'description', 'is_archived', 'reminder',
                                                                'user', 'color', 'is_pinned', 'is_deleted','label')
            print(type(note_data))

            data_list = []
            for i in note_data:
                data_list.append(i)
            print(data_list)
            z = json.dumps(data_list)

            print("zzzzzzzz type", type(z))
            print(z)
            res['message'] = "Showing data."
            res['data'] = z
            res['success'] = True
            return HttpResponse(z)

        except Exception as e:
            print(res, e)


class UpdateNote(UpdateAPIView):
    """Update Notes API"""

    serializer_class = NoteSerializer
    queryset = Note.objects.all()

    def post(self, request, *args, **kwargs):
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            queryset = Note.objects.get(pk=request.data['id'])

            print(queryset)

            header_token = request.META['HTTP_AUTHORIZATION']
            userdata = jwt.decode(header_token, "Cypher", algorithm='HS256')
            uid = userdata['user_id']

            item = Note.objects.get(pk=request.data['id'])
            print(item)
            print(item.id)
            title = request.data['title']
            des = request.data['description']
            color = request.data['color']
            remainder = request.data['reminder']
            # archive = request.data['is_archived']
            # pinned = request.data['is_pinned']
            # deletenote = request.data['delete']

            item.title = title
            item.description = des
            item.color = color
            item.reminder = remainder
            # item.is_archived = archive
            # item.is_pinned = pinned
            # item.is_deleted = deletenote
            item.save()

            res['message'] = "Update Successfully"
            res['success'] = True

            return Response(res)
            # return HttpResponse(res)
        except Exception as e:
            print(res, e)


class DeleteNote(UpdateAPIView):
    """Delete Notes API"""

    serializer_class = NoteSerializer
    queryset = Note.objects.all()

    def post(self, request, *args, **kwargs):
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            queryset = Note.objects.get(pk=request.data['id'])
            item = Note.objects.get(pk=request.data['id'])
            print(item)
            print(item.id)
            delete = request.data['is_deleted']
            item.is_deleted = delete
            item.save()
            res['message'] = "Update Successfully"
            res['success'] = True
            return Response(res)
        except Exception as e:
            print(res, e)


class PinUnpinNote(UpdateAPIView):
    """ PinUnpin Notes API """

    serializer_class = NoteSerializer
    queryset = Note.objects.all()

    def post(self, request, *args, **kwargs):
        try:
            res = {
                'message': 'Something bad happened',
                'success': False
            }
            queryset = Note.objects.get(pk=request.data['id'])
            item = Note.objects.get(pk=request.data['id'])
            print(item)
            print(item.id)
            pin = request.data['is_pinned']
            item.is_deleted = pin
            item.save()
            res['message'] = "Update Successfully"
            res['success'] = True
            return Response(res)
        except Exception as e:
            print(res, e)


# def login_required(f):
#     def check_login_and_call(request, *args, **kwargs):
#         authentication = request.META.get('HTTP_AUTHORIZATION', b'')
#         if isinstance(authentication, str):
#             authentication = authentication.encode(HTTP_HEADER_ENCODING)
#         key = authentication.split()
#         if not key or len(key) != 2:
#             raise PermissionDenied('Authentication failed.')
#         user, token = authenticate_credentials(key[1])
#         return f(request, *args, **kwargs)
#     return check_login_and_call

class Reminder(View):
    """Reminder notes API"""

    def get(self, request):
        global note_data

        '''
        print('-------',request.META['HTTP_AUTHORIZATION'])
        uid=request.META['HTTP_AUTHORIZATION']
        '''

        uid = request.META['HTTP_AUTHORIZATION']
        userdata = jwt.decode(uid, "Cypher", algorithm='HS256')
        uid = userdata['user_id']

        res = {
            'message': 'Something bad happened',
            'data': {},
            'success': False
        }
        try:

            note_data = Note.objects.filter(user_id=uid).values('id', 'title', 'description', 'reminder', )
            rem_notes = []
            for i in note_data:
                if i['reminder']:
                    rem_notes.append(i)
            print(rem_notes)
            z = json.dumps(rem_notes)
            return HttpResponse(z)
        except Exception as e:
            print(res, e)
