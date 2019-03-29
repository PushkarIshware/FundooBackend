from django.forms import forms
from rest_framework import serializers
from django.contrib.auth import get_user_model
# from django.contrib.auth.models import User


User = get_user_model()

# Register serializer for storing New user to database

class registrationSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=20)
    password = serializers.CharField(style={'input_type': 'password'})
    email = serializers.RegexField(regex=r'^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$',
                                   required=True)

    class Meta:
        model = User
        fields = ('username',
                  'email',
                  'password',
                  )

    def clean(self):
        cleaned_data = super(registrationSerializer, self).clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password != confirm_password:
            raise forms.ValidationError(
                "password and confirm_password does not match")

