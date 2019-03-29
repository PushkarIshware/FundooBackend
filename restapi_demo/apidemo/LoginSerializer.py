"""
******************************************************************************
* Purpose:  Login Serializer.
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   11-3-2018
*
******************************************************************************
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.contrib.auth.models import User

User = get_user_model()


# login serializer for checking user credentials

class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=20)
    password = serializers.CharField(style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('username', 'password',)
