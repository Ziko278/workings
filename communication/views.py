from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db.models.functions import Lower
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.messages.views import SuccessMessageMixin, messages
from django.views.generic import TemplateView
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required, permission_required
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.mail import EmailMessage, send_mail, get_connection, EmailMultiAlternatives
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from num2words import num2words
from django.conf import settings

from admin_site.models import SiteInfoModel
from communication.forms import SMTPConfigurationForm
from communication.models import *

from django.core.mail import EmailMessage, get_connection
from django.template.loader import render_to_string
from django.utils.html import strip_tags


def send_custom_email(subject, recipient_list, email_id, template_name, context, attachments=None):
    # Set up email backend

    # Render HTML content from template
    html_content = render_to_string(template_name, context)

    # Create plain text version by stripping HTML tags
    plain_content = strip_tags(html_content)

    # Create email message with alternatives (HTML and plain text)
    email = EmailMultiAlternatives(
        subject=subject,
        body=plain_content,
        from_email=settings.EMAIL_HOST_USER,
        to=recipient_list,
    )
    email.attach_alternative(html_content, "text/html")

    if attachments:
        for attachment in attachments:
            email.attach(*attachment)  # Unpacks (file_name, file_content, mime_type)

    # Send the email
    try:
        mail_sent = email.send()
    except Exception as e:
        mail_sent = False

    return mail_sent


class SMTPConfigurationCreateView(LoginRequiredMixin, SuccessMessageMixin, CreateView):
    model = SMTPConfigurationModel
    form_class = SMTPConfigurationForm
    success_message = 'Email Configuration Added Successfully'
    template_name = 'communication/smtp_configuration/index.html'

    def get_success_url(self):
        return reverse('smtp_configuration_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['smtp_configuration_list'] = SMTPConfigurationModel.objects.all().order_by('name')
        return context


class SMTPConfigurationListView(LoginRequiredMixin, ListView):
    model = SMTPConfigurationModel
    fields = '__all__'
    template_name = 'communication/smtp_configuration/index.html'
    context_object_name = "smtp_configuration_list"

    def get_queryset(self):
        return SMTPConfigurationModel.objects.all().order_by('name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = SMTPConfigurationForm

        return context


class SMTPConfigurationUpdateView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    model = SMTPConfigurationModel
    form_class = SMTPConfigurationForm
    success_message = 'Email Configuration Updated Successfully'
    template_name = 'communication/smtp_configuration/index.html'

    def get_success_url(self):
        return reverse('smtp_configuration_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['smtp_configuration_list'] = SMTPConfigurationModel.objects.all().order_by('name')

        return context


class SMTPConfigurationDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = SMTPConfigurationModel
    success_message = 'Email Configuration Deleted Successfully'
    fields = '__all__'
    template_name = 'communication/smtp_configuration/delete.html'
    context_object_name = "smtp_configuration"

    def get_success_url(self):
        return reverse("smtp_configuration_index")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context
