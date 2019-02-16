from django.test import TestCase
#
# # Create your tests here.
# import unittest
#
# from .views import test1
#
#
# class TestBasic(unittest.TestCase):
#
#     def test_test1(self):
#         res = test1()
#         self.assertEqual(res, "hi")
#
# # if __name__ == "__main__":
# #     unittest.main()
from rest_framework.test import APIRequestFactory

# Using the standard RequestFactory API to create a form POST request
factory = APIRequestFactory()
request = factory.get('127.0.0.1:8000/', {'title': 'new idea'})