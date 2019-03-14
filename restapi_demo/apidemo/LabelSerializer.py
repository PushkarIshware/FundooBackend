"""
******************************************************************************
* Purpose:  Label Serializer.
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   11-3-2018
*
******************************************************************************
"""

from rest_framework import serializers
from .models import Label


class LabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Label
        fields = ('id','label_name', 'user')