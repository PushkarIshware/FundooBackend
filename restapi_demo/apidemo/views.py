from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from rest_framework import generics
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

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
    """
    Login API
    """

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
                    # res['user_id'] = user_id.id
                    # tok = Token.objects.get_or_create(user=user)
                    # print("tok issssssssss------>", tok)
                    return Response(res)
                else:
                    return Response(res)
            if user is None:
                return Response(res)
        except Exception as e:
            print(e)
            return Response(res)


def UploadImg(request):
    if request.method == "POST":
        # username = request.data['username']
        username = request.POST.get('username')
        photo = request.POST.get('pic')
        print(photo)
        # photo = request.data['photo']
        # print(username, " ", photo)
        # pic = Image.open(photo, 'r')
        # photo.show()
        img = request.FILES['pic']
        image = Image.open(img, 'r')
        # image.show()
        #  path=image.file.path
        # image.show()
        s3 = boto3.client('s3')
        username = str(username + ".jpeg")

        # s3.Bucket('fundooapp').put_object(Body=request.FILES['pic'], Key=key)
        s3.upload_fileobj(img, 'fundooapp', Key=username)
        return JsonResponse({"msg": "recieved at django"})
    else:
        return render(request, 'profile.html', {})


class AddNote(CreateAPIView):
    """Add Notes API"""

    serializer_class = NoteSerializer

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

        res = {
            'message': 'Something bad happened',
            'data': {},
            'success': False
        }
        try:
            note_data = Note.objects.filter(user_id=uid).values()
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


# class UpdateNote(APIView):
#     serializer_class = NoteSerializer
#
#     # def put(self, request, pk):
#     def post(self, request, pk):
#
#         print("inside POST method")
#         """API for update the notes"""
#
#         res = {
#             'message': 'Something bad happened',
#             'data': {},
#             'success': False
#         }
#
#         uid = request.META['HTTP_AUTHORIZATION']
#         print(type(uid))
#         print("uid -------", uid)
#         userdata = jwt.decode(uid, "Cypher", algorithm='HS256')
#         uid = userdata['user_id']
#
#         try:
#             note = Note.objects.get(pk=pk)
#             print("noteeeeeee id", note.id)
#         except Exception as e:
#             print(e)
#             return JsonResponse(res)
#
#         # serializer = NoteSerializer(note.id, data=request.data)
#         serializer = NoteSerializer(note, data=request.data)
#         if serializer.is_valid():
#             # serializer.save(user_id=uid)
#             serializer.save()
#             res = {
#                 'message': 'Updated Successfully',
#                 'data': serializer.data,
#                 'success': True
#             }
#             return HttpResponse(res['data'])
#             #return Response(res['data'])
#         #return Response(res['message'])
#         return HttpResponse(res)

# def UpdateNote(request, pk):
#     res = {
#         'message': 'ID not found',
#         'data': {},
#         'success': False
#     }
#     print(request.body)
#     #
#     # try:
#     #     print("inside try.............")
#     #
#     #     note = Note.objects.get(id=pk)
#     #
#     #     note_id = note.id
#     #     print('note id ', note_id)
#     #     title = request.POST.get('id')
#     #     description = request.POST.get('description')
#     #
#     #     print("title and discription", title, "    ", description)
#     #
#     #     # ctime = request.POST.get('ctime')
#     #     # remainder = request.POST.get('remainder')
#     #     # colla = request.POST.get('colla')
#     #
#     #     # note.title = title
#     #     # note.description = description
#     #
#     #     # note.created_time=ctime
#     #     # note.remainder=remainder
#     #     # note.collaborate=colla
#     #     # if serializer.is_valid():
#     #
#     #     #note.save()
#     return HttpResponse(request.body)
#
#     # except Exception as e:
#     #     print('exception', e)



class UpdateNote(UpdateAPIView):

    """Add Notes API"""

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

            #
            # header_token = request.META['HTTP_AUTHORIZATION']
            # userdata = jwt.decode(header_token, "Cypher", algorithm='HS256')
            # uid = userdata['user_id']

            item = Note.objects.get(pk=request.data['id'])
            print(item)
            print(item.id)
            title = request.data['title']
            des = request.data['description']
            color = request.data['color']
            archive = request.data['archive']

            item.title = title
            item.description = des
            item.color = color
            item.is_archived = archive
            item.save()

            return Response(res)
        except Exception as e:
            print(res)