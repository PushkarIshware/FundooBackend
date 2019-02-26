from django.contrib.auth.models import User
from django.db import models

from django.db import models
from django.utils import timezone
from django.core.validators import MaxValueValidator, MinValueValidator


# Create your models here.
class Note(models.Model):
    title = models.CharField(max_length=150, default=None)
    description = models.TextField()
    #created_time = models.DateTimeField(auto_now_add=True, null=True)
    reminder = models.CharField(default=None, null=True, max_length=25)
    is_archived = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    color = models.CharField(default=None, max_length=50, blank=True, null=True)
    image = models.ImageField(default=None, null=True)
    trash = models.BooleanField(default=False)
    is_pinned = models.BooleanField(default=False)
    label = models.CharField(max_length=50, default=None, null=True)
    collaborate = models.ManyToManyField(User, null=True, blank=True, related_name='collaborated_user')
    #user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_id', null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owner', null=True, blank=True)


    def __str__(self):
        return self.title+" "+self.description
