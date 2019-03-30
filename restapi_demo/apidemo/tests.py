from django.test import TestCase
# #
# # # Create your tests here.
# # import unittest
# #
# # from .views import test1
# #
# #
# # class TestBasic(unittest.TestCase):
# #
# #     def test_test1(self):
# #         res = test1()
# #         self.assertEqual(res, "hi")
# #
# # # if __name__ == "__main__":
# # #     unittest.main()
# from rest_framework.test import APIRequestFactory
#
# # Using the standard RequestFactory API to create a form POST request
# factory = APIRequestFactory()
# request = factory.get('127.0.0.1:8000/', {'title': 'new idea'})

# from django.contrib.auth.models import User
# import os
# import pytest
#
# pytestmark = pytest.mark.django_db
#
#
# def login(request):
#     user = User.objects.create(username="nikhil", password='realme123456')
#     response = request.post('http://127.0.0.1:8000/api/login/',
#                             {'username': 'nikhil', 'password': 'realme123456'})
#     assert response.status_code == 200
#
#
# # if __name__ == '__main__':
# #     os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tangle.settings')
# #     import django
# #
# #     django.setup()
from django.urls import reverse
from rest_framework.test import APITestCase
from django.contrib.auth.models import User
from rest_framework import status


class AccountsTest(APITestCase):
    # def setUp(self):
    #     # We want to go ahead and originally create a user.
    #     self.test_user = User.objects.create_user('testuser', 'test@example.com', 'testpassword')
    #
    #     # URL for creating an account.
    #     self.create_url = reverse('RestRegistration')

    def test_create_user(self):
        data = {
            'username': 'foobar',
            'email': 'foobar@example.com',
            'password': 'somepassword'
        }
        response = self.client.post(self.create_url, data, format='json')
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['username'], data['username'])
        self.assertEqual(response.data['email'], data['email'])
        #self.assertFalse('password' in response.data)