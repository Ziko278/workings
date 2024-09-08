from django.db import models
from django.contrib.auth.models import User


class RecentActivityModel(models.Model):
    category = models.CharField(max_length=100)
    subject = models.CharField(max_length=250)
    reference_id = models.IntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)


class SMTPConfigurationModel(models.Model):
    name = models.CharField(max_length=200)
    email = models.EmailField()
    host = models.CharField(max_length=200)
    port = models.PositiveIntegerField()
    use_tls = models.BooleanField(default=True)
    password = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.name.upper()


class CommunicationSettingModel(models.Model):
    default_smtp = models.ForeignKey(SMTPConfigurationModel, on_delete=models.SET_NULL, null=True, blank=True)


class ContactModel(models.Model):
    name = models.CharField(max_length=200)
    email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.name.upper()


class TemplateDataModel(models.Model):
    template = models.CharField(max_length=200)
    data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)

