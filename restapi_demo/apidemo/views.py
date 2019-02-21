import io

from allauth.account.forms import SetPasswordForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordResetForm, PasswordChangeForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordContextMixin
from django.shortcuts import render, resolve_url
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST
from django.views.generic import TemplateView, FormView
from rest_auth.serializers import UserModel
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.reverse import reverse_lazy

from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import get_user_model, authenticate, login, update_session_auth_hash
import jwt
import json
from django.contrib.auth.models import User
import re
from django.http import JsonResponse
from PIL import Image
import boto3

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


from .serializers import registrationSerializer, LoginSerializer, NoteSerializer


# @require_POST
class RestRegistration(CreateAPIView):
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


# @require_POST
class RestLogin(CreateAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        res = {"message": "something bad happened",
               "data": {},
               "success": False}
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
                    payload = {'username': username, 'password': password}
                    # token = jwt.encode(payload, "secret_key", algorithm='HS256').decode('utf-8')
                    jwt_token = {
                        'token': jwt.encode(payload, "Cypher", algorithm='HS256').decode('utf-8')
                    }
                    print(jwt_token)
                    token = jwt_token['token']
                    res['message'] = "Logged in Successfully"
                    res['data'] = token
                    res['success'] = True
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


from rest_framework import viewsets
from .models import Notes


class AddNote(CreateAPIView):
    serializer_class = NoteSerializer  # serializer to add note(specifies and validate )

    def post(self, request, *args, **kwargs):
        try:
            # print(request.data)
            # print(request.data['remainder'])

            res = {  # Response information .
                'message': 'Something bad happened',
                'data': {},
                'success': False
            }

            print('user--->', request.data['user'])
            serializer = NoteSerializer(data=request.data)
            # check serialized data is valid or not

            if request.data['title'] and request.data[
                'description'] is None:  # if title and description is not provided.
                raise Exception("Please add some information ")

            if serializer.is_valid():
                # if valid then save it
                serializer.save()
                # in response return data in json format
                res['message'] = "note added"
                res['success'] = True
                return Response(res)

                # else return error msg in response
            return Response(res)
        except Exception as e:
            print(e)
            # return redirect(reverse('getnotes'))
