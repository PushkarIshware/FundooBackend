import pytest
from django.contrib.auth.models import User
from apidemo import views
from django.test import RequestFactory
from apidemo import models
from .utils import LoginableTestCase
import json


@pytest.mark.django_db
class TestUserView(LoginableTestCase):



    def test_login(self):
        data = {
            'username': 'nikhil',
            'password': 'realme123456',
        }
        data = json.dumps(data)
        print(data)
        res = self.client.post('login_user/', data=data)
        assert res.status_code == 201


