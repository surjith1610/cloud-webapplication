import uuid
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils.timezone import now
from datetime import timedelta

class User(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid.uuid4, editable=False, unique=True)
    email =  models.EmailField(max_length=100, unique=True)
    password =  models.CharField(max_length=128)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    account_created = models.DateTimeField(auto_now_add=True)
    account_updated = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=255, unique=True, null=True, blank=True)
    expiration_time = models.DateTimeField(null=True, blank=True)  

    def __str__(self):
        return self.email

class Image(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    file_name = models.CharField(max_length=255)
    url = models.URLField()
    upload_date = models.DateTimeField(auto_now_add=True)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='images')