from django.forms import forms
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
import re
from .models import Note, Label

User = get_user_model()


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


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=20)
    password = serializers.CharField(style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ('username', 'password',)


class NoteSerializer(serializers.ModelSerializer):
    # Serializer for Notes

    class Meta:
        model = Note
        fields = ('title', 'description', 'is_archived', 'reminder', 'user', 'color', 'is_pinned', 'is_deleted', 'label')


class LabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Label
        fields = ('label_name', 'user')
