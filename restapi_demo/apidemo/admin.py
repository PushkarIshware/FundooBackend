from django.contrib import admin

# Register your models here.
from .models import Note, Label

admin.site.register(Note)
admin.site.register(Label)