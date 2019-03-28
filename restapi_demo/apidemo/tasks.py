import string

from django.contrib.auth.models import User
from django.http import request
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .tokens import account_activation_token
from .views import *

from celery import shared_task


@shared_task
def demo_celery():
    return 'celery-------------------------------works'


@shared_task
def Send_mail(username, email):
    print(username)
    user = User.objects.get(username=username)
    print(email)
    message = render_to_string('acc_active_email.html', {
        'user': user,
        'domain': 'http://127.0.0.1:8000',
        # 'domain': request.META.get('HTTP_HOST'),
        # 'domain': os.getenv("DOMAIN"),
        'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
        'token': account_activation_token.make_token(user),
    })
    mail_subject = 'Activate your account...'
    to_email = email
    send_email = EmailMessage(mail_subject, message, to=[to_email])
    send_email.send()
    return "email sent"
