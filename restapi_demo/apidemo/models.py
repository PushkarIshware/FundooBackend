from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.db import models

from django.db import models
from django.utils import timezone
from django.core.validators import MaxValueValidator, MinValueValidator


# Note model
class Note(models.Model):
    title = models.CharField(max_length=150, default=None)  # for add title
    description = models.TextField()  # for add descriptions
    created_time = models.DateTimeField(auto_now_add=True, null=True)  # for created time which is auto
    reminder = models.CharField(default=None, null=True, max_length=25)  # for set reminders notes
    is_archived = models.BooleanField(default=False)  # for archive notes
    is_deleted = models.BooleanField(default=False)  # for delete notes
    color = models.CharField(default=None, max_length=50, blank=True, null=True)  # for set color
    image = models.ImageField(default=None, null=True)  # for set image to notes
    trash = models.BooleanField(default=False)  # for trash notes
    is_pinned = models.BooleanField(default=False)  # for set pin unpin notes
    label = models.CharField(max_length=50, default=None, null=True)  # for label names
    collaborate = models.ManyToManyField(User, null=True, blank=True, related_name='collaborated_user')  # for
    # collaborator (MtM fields)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owner', null=True, blank=True)  # for

    # storing user details

    def __str__(self):
        return self.title + " " + self.description


# Label model
class Label(models.Model):
    label_name = models.CharField(max_length=50)  # for label name
    created_time = models.DateTimeField(auto_now_add=True, null=True)  # created time of labels
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)  # user details

    def __str__(self):
        return self.label_name


# Map label model
class Map_Label(models.Model):
    label_id = models.ForeignKey(Label, null=True, blank=True, on_delete=models.CASCADE)
    # for label id
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    # user details
    created_time = models.DateTimeField(auto_now_add=True, null=True)
    # for created time of labels
    note = models.ForeignKey(Note, on_delete=models.CASCADE, null=True, blank=True)
    # for which note we adding given label
    map_label_name = models.CharField(max_length=50)
    # mapped label name

    def __str__(self):
        return str(self.note)
