"""
******************************************************************************
* Purpose:  Note Serializer.
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
from .models import Note

User = get_user_model()


class NoteSerializer(serializers.ModelSerializer):
    # Serializer for Notes

    class Meta:
        model = Note
        fields = ('title', 'description', 'is_archived',
                  'reminder', 'user', 'color', 'is_pinned',
                  'is_deleted', 'label')
