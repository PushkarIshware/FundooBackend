from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.contrib.auth.models import User

User = get_user_model()


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=20)
    password = serializers.CharField(style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('username', 'password',)
