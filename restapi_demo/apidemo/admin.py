from django.contrib import admin

# Register your models here.
from .models import Note, Label, Map_Label

admin.site.register(Note)
admin.site.register(Label)
admin.site.register(Map_Label)