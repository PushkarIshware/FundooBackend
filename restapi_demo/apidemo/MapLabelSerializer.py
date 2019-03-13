from rest_framework import serializers
from .models import Map_Label


class MapLabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Map_Label
        fields = ('label_id', 'user', 'note', 'map_label_name')
