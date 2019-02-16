# import pytest
# from django.contrib.auth.models import User
#
# from rest_framework.test import APIClient
#
# @pytest.fixture
# def client():
#     return APIClient()
#
# @pytest.fixture
# def users():
#     u1 = User.objects.create(username='nikhil')
#     u1.set_password('nikhil')
#     u1.save()
#     u2 = User.objects.create(username='realme123456')
#     u2.set_password('realme123456')
#     u2.save()
#     return u1, u2
