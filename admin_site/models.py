import barcode
from django.contrib.auth.models import User
from django.db import models


class SiteInfoModel(models.Model):
    name = models.CharField(max_length=150)
    short_name = models.CharField(max_length=50)
    mobile = models.CharField(max_length=20)
    email = models.EmailField(max_length=100)
    address = models.CharField(max_length=255, null=True, blank=True)

    logo = models.FileField(upload_to='images/setting/logo')

    # social media handles
    facebook_handle = models.CharField(max_length=100, null=True, blank=True)
    instagram_handle = models.CharField(max_length=100, null=True, blank=True)
    twitter_handle = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.short_name.upper()


class SiteSettingModel(models.Model):
    email_confirmation = models.BooleanField(default=False)

    def __str__(self):
        return 'SITE SETTING'


class MediaModel(models.Model):
    name = models.CharField(max_length=150)
    image = models.FileField(upload_to='images/uploaded')

    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.name.upper()



