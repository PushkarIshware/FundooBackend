from django.forms import forms
from django.http import HttpResponse
from rest_framework import serializers
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.validators import UniqueValidator
from django.contrib.auth import get_user_model
# serializers used to convert models into JSON .
from django.contrib.contenttypes.models import ContentType

User = get_user_model()
from rest_framework import status, exceptions
from django.http import HttpResponse
from rest_framework.authentication import get_authorization_header, BaseAuthentication
from django.contrib.auth.models import User
import jwt
import json
from rest_framework.serializers import (HyperlinkedIdentityField, ModelSerializer, SerializerMethodField,
                                        ValidationError)
from django.contrib.auth import authenticate
from rest_framework import exceptions
import re


class registrationSerializer(serializers.ModelSerializer):
    # username = serializers.CharField(max_length=20)
    # password = serializers.CharField(style={'input_type': 'password'})
    # # confirm_password=serializers.CharField(style={'input_type':'password'})
    # email = serializers.RegexField(regex=r'^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$',
    #                                required=True)

    class Meta:  # inner class provides a metadata to ModelForm Class.

        model = User  # Database Model to  store the data in .
        # model=RestRegistration         # Stores data in  registration model.
        # fields='__all__'               # fields used as queryset.
        fields = ('username',
                  'email',
                  'password1',
                  'password2'
                  )

    # def clean(self):
    #     cleaned_data = super(registrationSerializer, self).clean()
    #     password = cleaned_data.get("password")
    #     confirm_password = cleaned_data.get("confirm_password")
    #
    #     if password != confirm_password:
    #         raise forms.ValidationError(
    #             "password and confirm_password does not match")


class TokenAuthentication(BaseAuthentication,
                          serializers.ModelSerializer):  # provides a way to create serializer class with fields in Model.
    username = serializers.CharField(max_length=20)
    password = serializers.CharField(style={'input_type': 'password'})

    # confirm_password=serializers.CharField(style={'input_type': 'password'})
    class Meta:  # inner class provides a metadata to ModelForm Class.
        model = User  # sets Model as User Model.
        fields = ['username',
                  'password']

        def get_model(self):
            return User

        def authenticate_credentials(self, token):

            """This method is used if we pass our token to other app or method
            this will validated if user is valid or not by decoding the token"""

            # model = self.get_model()
            payload = jwt.decode(token, "SECRET_KEY", algorithm='HS256')  # decodes the token
            username = payload['username']  # gets username from decoded token
            password = payload['password']  # gets password from decoded token
            msg = {'Error': "Token mismatch", 'status': "401"}
            try:

                user = User.objects.get(
                    username=username,
                    password=password,
                    is_active=True
                )

                if not user.token['token'] == token:
                    raise exceptions.AuthenticationFailed(msg)

            except jwt.ExpiredSignature or jwt.DecodeError or jwt.InvalidTokenError:
                return HttpResponse({'Error': "Token is invalid"}, status="403")
            except User.DoesNotExist:
                return HttpResponse({'Error': "Internal server error"}, status="500")

            return (user, token)

        def authenticate_header(self, request, token):
            return token
