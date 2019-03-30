"""
******************************************************************************
* Purpose:  Map Label Serializer.
*
* @author:  Pushkar Ishware
* @version: 3.7
* @since:   11-3-2018
*
******************************************************************************
"""

from rest_framework import serializers
from .models import Map_Label


# map serializer for storing map labels to particular note

class MapLabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Map_Label
        fields = ('label_id', 'user', 'note', 'map_label_name')
