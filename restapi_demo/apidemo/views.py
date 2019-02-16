from allauth.account.forms import default_token_generator, SetPasswordForm
from django.contrib.auth import login, authenticate, update_session_auth_hash

from django.contrib import messages, auth
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string

from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.http import HttpResponse, HttpRequest, HttpResponsePermanentRedirect, HttpResponseRedirect
from django.shortcuts import render, resolve_url
from django.contrib.auth import get_user_model, authenticate
import jwt
import json
from django.contrib.auth.models import User
import re
from django.http import JsonResponse

User = get_user_model()


def index(request):  # homepage
    return render(request, 'index.html', {})


def login_page(request):  # login page
    return render(request, 'login.html')


def logout(request):
    auth.logout(request)
    return render(request, 'login.html')


'''
sign up method which takes 4 arguments ie username, email, password and confirm password.
and generate registration link and send it to corresponding email id.
if valid then go to login page
else show error message
'''


def Signup(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password1 = data.get('password1')
        password2 = data.get('password2')

        print(username, " ", email, " ", password1, " ", password2)

        if username and email and password1 and password2 is not "":
            print("if block")
            if User.objects.filter(username=username).exists():  # for user and email also we can try this
                return JsonResponse({"msg": "username already present"})

            if not re.match(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$', email):
                return JsonResponse({"msg": "Not proper email"})

            if password1 == password2:
                User.objects.create_user(username=username, email=email, password=password1, is_active=True)
                user = User.objects.get(username=username)
                message = render_to_string('acc_active_email.html', {
                    'user': user,
                    # 'domain': 'http://127.0.0.1:8000',
                    'domain': 'localhost:4200/login',
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                    'token': account_activation_token.make_token(user),
                })
                mail_subject = 'Activate your account...'
                to_email = email
                send_email = EmailMessage(mail_subject, message, to=[to_email])
                send_email.send()

            else:
                return JsonResponse({"msg": "not matching password"})
            json_data = {
                "username": username,
                "email": email,
                "password1": password1,
                "password2": password2,
                "msg": "please got to your mail and activate your account"
            }
            return JsonResponse(json_data)

        else:
            print("else block")
            return JsonResponse({"msg": "something is empty"})
    else:

        # form = SignupForm()
        return JsonResponse({"msg": "reg failed"})


'''
this is login method which is takes 2 arguments ie. username and password
if details are correct go to dashboard 
else show error message
'''


def login_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        print('data from Angular', data)
        username = data.get('username')
        print(username)

        password = data.get('password')
        print(password)
        user = authenticate(username=username, password=password)
        if user:
            print("if part")
            if user.is_active:
                login(request, user)
                payload = {'username': username,
                           'password': password, }
                token = jwt.encode(payload, "secret_key", algorithm='HS256').decode('utf-8')
                jwt_token = {
                    'token': token
                }
                print(jwt_token)

                json_data = {
                    "success": True,
                    'username': username,
                    'password': password,
                    'token': token,
                    "message": "successful login"
                }
                dump = json.dumps(json_data)
                # return JsonResponse(dump)
                return HttpResponse(dump, content_type="application/json")

            else:
                return HttpResponse("Your account was inactive.")
        else:
            print("else part")
            json_data = {

                "success": False,
                "message": "UNsuccessful login"
            }
            return JsonResponse(json_data)

    else:
        json_data = {
            "success": False,
            "message": "UNSUCCESSFUL login"
        }
        return JsonResponse(json_data)


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
