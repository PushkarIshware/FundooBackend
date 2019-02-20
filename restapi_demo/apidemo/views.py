from django.shortcuts import render
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.views.decorators.http import require_POST
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.contrib.auth import get_user_model, authenticate
import jwt
import json
from django.contrib.auth.models import User
import re
from django.http import JsonResponse

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


from .serializers import registrationSerializer, LoginSerializer


# @require_POST
class RestRegistration(CreateAPIView):
    serializer_class = registrationSerializer

    def post(self, request, *args, **kwargs):
        print(request.data)
        username = request.data['username']
        email = request.data['email']
        password = request.data['password1']
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

        return JsonResponse({'key': "Registered"})


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


from PIL import Image

import boto3
def profile_pic(request, *args, **kwargs):
    if request.method=="POST":
       #username = request.data['username']
        username = request.POST.get('username')
        photo = request.POST.get('pic')
        print(photo)
        #photo = request.data['photo']
        # print(username, " ", photo)
        # pic = Image.open(photo, 'r')
        #photo.show()
        img=request.FILES['pic']
        image = Image.open(img)
        #image.show()
        s3 = boto3.client('s3')
        key=username + ".jpeg"
        s3.upload_fileobj(image,'fundooapp',Key=key)
        return JsonResponse({"msg": "recieved at django"})
    else:return render(request,'profile.html',{})



