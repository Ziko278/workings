from datetime import datetime, date, timedelta

from django.contrib.auth.models import User
from django.db import models


class UserProfileModel(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=True, related_name='user_profile')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    username = models.EmailField()
    phone_number = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    photo = models.ImageField(upload_to='user/profile_photo', blank=True, null=True)
    referrals = models.ManyToManyField('self', blank=True)
    email_verified = models.BooleanField(default=False, blank=True)
    last_verification_code = models.CharField(max_length=10, null=True, blank=True)

    def __str__(self):
        return self.first_name.title() + ' ' + self.last_name.title()


class UserWalletModel(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=True, related_name='user_wallet')
    balance = models.FloatField(default=0.0)

    def __str__(self):
        return self.user.username.title()


class UserFundingModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, related_name='funding_list')
    amount = models.FloatField()
    status = models.CharField(max_length=30, blank=True, default='pending')  # pending, failed and completed
    created_at = models.DateTimeField(auto_now_add=True, blank=True)

    def __str__(self):
        return self.user.__str__()


