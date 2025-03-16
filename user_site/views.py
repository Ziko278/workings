import json
import random
import re
import requests
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail, BadHeaderError
from django.db.models import Sum, Q
from django.db.models.functions import Lower
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.views.generic import TemplateView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.views.decorators.http import require_POST
from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError
from datetime import datetime, timedelta
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse, JsonResponse, Http404, HttpRequest
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.messages.views import SuccessMessageMixin, messages
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordResetForm, SetPasswordForm
from num2words import num2words

from admin_site.forms import MediaForm
from admin_site.models import SiteInfoModel, SiteSettingModel, MediaModel
from communication.forms import ContactForm, SMTPConfigurationForm
from communication.models import ContactModel, SMTPConfigurationModel, TemplateDataModel
from communication.views import send_custom_email

from user_site.forms import UserProfileForm, LoginForm, SignUpForm, UserFundingForm,UserProfileEditForm

from user_site.models import UserProfileModel, UserFundingModel, UserWalletModel
import math


def round_to_sf(number, sf):
    if number == 0:
        return 0
    # Compute the factor for rounding
    factor = 10 ** (sf - int(math.floor(math.log10(abs(number)))) - 1)
    return round(number * factor) / factor


def user_signup_view(request):
    if request.method == 'POST':
        user_form = SignUpForm(request.POST)
        profile_form = UserProfileForm(request.POST, request.FILES)
        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save()
            profile = profile_form.save(commit=False)
            profile.user = user
            profile.save()

            if user.id and profile.id:
                referral_id = request.GET.get('user_id') or request.POST.get('user_id') or None
                if referral_id:
                    try:
                        referer = UserProfileModel.objects.get(user__username=referral_id)
                        referer.referrals.add(profile)
                        site_setting = SiteSettingModel.objects.first()
                        if site_setting.referral_payment_before_bonus:
                            referer_wallet = UserWalletModel.objects.get(user=referer.user)
                            referer_wallet.referral_balance += site_setting.referral_bonus
                            referer_wallet.save()
                    except Exception:
                        pass

                messages.success(request, 'Account Created Successfully')
                return redirect(reverse('login'))
    else:
        user_form = SignUpForm
        profile_form = UserProfileForm
    context = {
        'user_form': user_form,
        'user_id': request.GET.get('user_id', None),
        'profile_form': profile_form,
        'site_setting': SiteSettingModel.objects.first(),
    }
    return render(request, 'user_site/register.html', context)


def user_signin_view(request):
    if request.method == 'POST':
        form = LoginForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            # try to log user by either username or password
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                try:
                    user = User.objects.get(email=username)
                except User.DoesNotExist:
                    user = None
            if not user:
                messages.error(request, 'Invalid Username or Email ')

            else:
                username = user.username
                user = authenticate(request, username=username, password=password)
                if user is not None:
                    if user.is_active:
                        login(request, user)

                        if 'remember_login' in request.POST:
                            request.session.set_expiry(0)
                            request.session.modified = True

                        user_profile = UserProfileModel.objects.get(user=request.user)
                        messages.success(request, 'Welcome Back {}'.format(user_profile.__str__()))
                        if not user_profile.email_verified:
                            return redirect(reverse('email_verify_1'))

                        nxt = request.GET.get("next", None)
                        if nxt:
                            return redirect(request.GET.get('next'))
                        return redirect(reverse('user_dashboard'))
                    else:
                        messages.error(request, 'Account not Activated')
                else:
                    messages.error(request, 'Invalid Credentials')
        else:
            messages.error(request, 'Invalid Credentials')
    else:
        form = LoginForm()
    context = {
        'form': form
    }
    return render(request, 'user_site/login.html', context)


def user_sign_out_view(request):
    logout(request)
    return redirect(reverse('login'))


@login_required
def email_verification_one(request):
    user_profile = UserProfileModel.objects.get(user=request.user)
    if user_profile.email_verified:
        messages.warning(request, 'Email Account Already Verified')
        return redirect(reverse('user_profile'))

    return render(request, 'user_site/account/email_verify_1.html')


@login_required
def email_verification_two(request):
    user_profile = UserProfileModel.objects.get(user=request.user)
    if user_profile.email_verified:
        messages.warning(request, 'Email Account Already Verified')
        return redirect(reverse('user_profile'))

    if request.method == 'POST':
        user_code = request.POST.get('code').strip()
        if user_code == user_profile.last_verification_code:
            user_profile.email_verified = True
            user_profile.save()
            messages.success(request, 'Email Successfully Verified')
            if not user_profile.identity_verified:
                return redirect(reverse('identity_verify'))
            if not user_profile.address_verified:
                return redirect(reverse('address_verify'))
            return redirect(reverse('user_profile'))
        else:
            messages.error(request, 'Invalid Verification Code')
        context = {}
    else:
        site_info = SiteInfoModel.objects.first()
        code = random.randrange(10000, 100000)
        context = {
            'code': code,
            'profile': user_profile
        }
        mail_sent = send_custom_email(
            subject='Email Verification Email for {}'.format(site_info.name.title()),
            recipient_list=[request.user.username],
            template_name='communication/template/verify_email.html',
            context=context,
            # attachments=[('bitcoin.jpg', requests.get(
            #     'https://roseofsharonhospital.ng/static/user_site/images/bitcoin.jpg').content, 'application/pdf')]

        )

        user_profile.last_verification_code = code
        user_profile.save()
        if mail_sent:
            context['mail_sent'] = True
        else:
            context['mail_sent'] = False
    return render(request, 'user_site/account/email_verify_2.html', context)


class UserDashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'user_site/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class UserProfileView(LoginRequiredMixin, TemplateView):
    template_name = 'user_site/account/profile.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = UserProfileModel.objects.get(user=self.request.user)
        context['user_profile'] = user
        context['form'] = UserProfileForm(instance=user)
        return context


class UserProfileChangeView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    model = UserProfileModel
    template_name = 'user_site/account/profile.html'
    form_class = UserProfileEditForm
    success_message = 'Profile Successfully Updated'

    def get_success_url(self):
        return reverse('user_profile')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = UserProfileModel.objects.get(user=self.request.user)
        context['user_profile'] = user
        context['form'] = UserProfileForm(instance=user)
        return context


class UserProfileVerificationView(LoginRequiredMixin, TemplateView):
    template_name = 'user_site/account/verification.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = UserProfileModel.objects.get(user=self.request.user)
        context['user_profile'] = user
        return context


class UserReferralView(LoginRequiredMixin, TemplateView):
    template_name = 'user_site/account/referral.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_profile = UserProfileModel.objects.get(user=self.request.user)
        context['user_profile'] = user_profile
        context['referral_link'] = reverse('register')
        context['domain'] = self.request.get_host()

        return context


@login_required
def user_change_password_view(request):
    if request.method == 'POST':
        current_password = request.POST['current_password']
        new_password1 = request.POST['new_password1']
        new_password2 = request.POST['new_password2']

        # Verify the current password
        if not request.user.check_password(current_password):
            messages.error(request, 'Incorrect current password.')
            return redirect(reverse('user_change_password'))

        # Check if the new passwords match
        if len(new_password1) < 8:
            messages.error(request, 'Password must have at least 8 characters.')
            return redirect(reverse('user_change_password'))

        if not re.match(r"^(?=.*[a-zA-Z])(?=.*\d).+$", new_password1):
            messages.error(request, 'Password must contain both letters and numbers.')
            return redirect(reverse('user_change_password'))

        if new_password1 != new_password2:
            messages.error(request, 'New passwords do not match.')
            return redirect(reverse('user_change_password'))

        # Update the user's password
        user = request.user
        user.set_password(new_password1)
        user.save()

        # Update the user's session with the new password
        update_session_auth_hash(request, user)

        logout(request)

        messages.success(request, 'Password successfully changed. Please log in with the new password.')
        return redirect('login')

    return render(request, 'user_site/account/change_password.html')


def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_user = User.objects.filter(email=data).first()
            if associated_user:
                subject = "Password Reset Requested"
                email_template_name = "password_reset_email.html"
                context = {
                    "email": associated_user.email,
                    'domain': get_current_site(request).domain,
                    'site_name': 'Your site',
                    "uid": urlsafe_base64_encode(force_bytes(associated_user.pk)),
                    "user": associated_user,
                    'token': default_token_generator.make_token(associated_user),
                    'protocol': 'http',
                }
                email = render_to_string(email_template_name, context)
                try:
                    send_mail(subject, email, 'your-email@gmail.com', [associated_user.email], fail_silently=False)
                except BadHeaderError:
                    messages.error(request, 'An Error has Occured, Try Later')
                    return redirect("password_reset")
                return redirect("password_reset_done")
    password_reset_form = PasswordResetForm()
    return render(request, "user_portal/password_reset.html", {"password_reset_form": password_reset_form})


def password_reset_confirm(request, uidb64=None, token=None):
    logout(request)
    if request.method == 'POST':
        form = SetPasswordForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            return redirect('password_reset_complete')
    else:
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            form = SetPasswordForm(user=user)
        else:
            return HttpResponse('Password reset link is invalid.')

    return render(request, 'password_reset_confirm.html', {'form': form})


class UserFundingListView(LoginRequiredMixin, ListView):
    model = UserFundingModel
    fields = '__all__'
    template_name = 'user_site/funding/index.html'
    context_object_name = "funding_list"

    def get_queryset(self):
        return UserFundingModel.objects.filter(user=self.request.user).order_by('id').reverse()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class MediaCreateView(LoginRequiredMixin, SuccessMessageMixin, CreateView):
    model = MediaModel
    form_class = MediaForm
    success_message = 'Media Added Successfully'
    template_name = 'user_site/media/index.html'

    def get_success_url(self):
        return reverse('user_media_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['media_list'] = MediaModel.objects.all().order_by('name')
        return context


class MediaListView(LoginRequiredMixin, ListView):
    model = MediaModel
    fields = '__all__'
    template_name = 'user_site/media/index.html'
    context_object_name = "media_list"

    def get_queryset(self):
        return MediaModel.objects.filter(user=self.request.user).order_by('name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        domain = self.request.get_host()  # Get the domain, e.g., 'yourdomain.com'
        protocol = 'https://' if self.request.is_secure() else 'http://'
        context['domain'] = protocol + domain  # Combine protocol and domain
        context['form'] = MediaForm
        return context


class MediaUpdateView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    model = MediaModel
    form_class = MediaForm
    success_message = 'Media Updated Successfully'
    template_name = 'user_site/media/index.html'

    def get_success_url(self):
        return reverse('user_media_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['media'] = MediaModel.objects.all().order_by('name')
        return context


class MediaDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = MediaModel
    success_message = 'Media Deleted Successfully'
    fields = '__all__'
    template_name = 'user_site/media/delete.html'
    context_object_name = "media"

    def get_success_url(self):
        return reverse('user_media_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class ContactCreateView(LoginRequiredMixin, SuccessMessageMixin, CreateView):
    model = ContactModel
    form_class = ContactForm
    success_message = 'Contact Added Successfully'
    template_name = 'user_site/contact/index.html'

    def get_success_url(self):
        return reverse('user_contact_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['contact_list'] = ContactModel.objects.all().order_by('name')
        return context


class ContactListView(LoginRequiredMixin, ListView):
    model = ContactModel
    fields = '__all__'
    template_name = 'user_site/contact/index.html'
    context_object_name = "contact_list"

    def get_queryset(self):
        return ContactModel.objects.filter(user=self.request.user).order_by('name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = ContactForm
        return context


class ContactUpdateView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    model = ContactModel
    form_class = ContactForm
    success_message = 'Contact Updated Successfully'
    template_name = 'user_site/contact/index.html'

    def get_success_url(self):
        return reverse('user_contact_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['contact'] = ContactModel.objects.all().order_by('name')
        return context


class ContactDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = ContactModel
    success_message = 'Contact Deleted Successfully'
    fields = '__all__'
    template_name = 'user_site/contact/delete.html'
    context_object_name = "contact"

    def get_success_url(self):
        return reverse('user_contact_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class SMTPConfigurationCreateView(LoginRequiredMixin, SuccessMessageMixin, CreateView):
    model = SMTPConfigurationModel
    form_class = SMTPConfigurationForm
    success_message = 'Email Configuration Added Successfully'
    template_name = 'user_site/smtp_configuration/index.html'

    def get_success_url(self):
        return reverse('smtp_configuration_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['smtp_configuration_list'] = SMTPConfigurationModel.objects.filter(user=self.request.user).order_by('name')
        return context


class SMTPConfigurationListView(LoginRequiredMixin, ListView):
    model = SMTPConfigurationModel
    fields = '__all__'
    template_name = 'user_site/smtp_configuration/index.html'
    context_object_name = "smtp_configuration_list"

    def get_queryset(self):
        return SMTPConfigurationModel.objects.filter(user=self.request.user).order_by('name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = SMTPConfigurationForm

        return context


class SMTPConfigurationUpdateView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    model = SMTPConfigurationModel
    form_class = SMTPConfigurationForm
    success_message = 'Email Configuration Updated Successfully'
    template_name = 'user_site/smtp_configuration/index.html'

    def get_success_url(self):
        return reverse('smtp_configuration_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['smtp_configuration_list'] = SMTPConfigurationModel.objects.filter(user=self.request.user).order_by('name')

        return context


class SMTPConfigurationDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = SMTPConfigurationModel
    success_message = 'Email Configuration Deleted Successfully'
    fields = '__all__'
    template_name = 'user_site/smtp_configuration/delete.html'
    context_object_name = "smtp_configuration"

    def get_success_url(self):
        return reverse("smtp_configuration_index")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class UserEmailTemplateView(LoginRequiredMixin, TemplateView):
    template_name = 'user_site/email_template/index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


def email_template_one_data(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        site_name = request.POST.get('site_name')
        logo = request.POST.get('logo')
        use_banner = 'use_banner' in request.POST
        banner_header = request.POST.get('banner_header')
        banner_description = request.POST.get('banner_description')
        body_intro = request.POST.get('body_intro')
        body_list = request.POST.get('body_list')
        body_list = [data.strip() for data in body_list.split('***')]
        body_conclusion = request.POST.get('body_conclusion')
        body_image = request.POST.get('body_image')
        body_image = [data.strip() for data in body_image.split(',')]
        footer_website = request.POST.get('footer_website')
        use_footer = 'use_footer' in request.POST

        dataset = {
            'title': title,
            'site_name': site_name,
            'logo': logo,
            'use_banner': use_banner,
            'banner_header': banner_header,
            'banner_description': banner_description,
            'body_intro': body_intro,
            'body_list': body_list,
            'body_conclusion': body_conclusion,
            'body_image': body_image,
            'footer_website': footer_website,
            'use_footer': use_footer
        }

        template_data = TemplateDataModel.objects.create(template='template_1', data=dataset, user=request.user)
        template_data.save()
        if template_data.id:
            messages.success(request, 'Email Data Saved Successfully')
            return redirect(reverse('user_mails'))

    return render(request, 'user_site/email_data/template_1.html')


def email_template_two_data(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        site_name = request.POST.get('site_name')
        logo = request.POST.get('logo')
        use_banner = 'use_banner' in request.POST
        banner_header = request.POST.get('banner_header')
        banner_description = request.POST.get('banner_description')
        body_intro = request.POST.get('body_intro')
        body_list = request.POST.get('body_list')
        body_list = [data.strip() for data in body_list.split('***')]
        body_conclusion = request.POST.get('body_conclusion')
        body_image = request.POST.get('body_image')
        body_image = [data.strip() for data in body_image.split(',')]
        footer_website = request.POST.get('footer_website')
        use_footer = 'use_footer' in request.POST

        dataset = {
            'title': title,
            'site_name': site_name,
            'logo': logo,
            'use_banner': use_banner,
            'banner_header': banner_header,
            'banner_description': banner_description,
            'body_intro': body_intro,
            'body_list': body_list,
            'body_conclusion': body_conclusion,
            'body_image': body_image,
            'footer_website': footer_website,
            'use_footer': use_footer
        }

        template_data = TemplateDataModel.objects.create(template='template_2', data=dataset, user=request.user)
        template_data.save()
        if template_data.id:
            messages.success(request, 'Email Data Saved Successfully')
            return redirect(reverse('user_mails'))

    return render(request, 'user_site/email_data/template_1.html')


def user_mails(request):
    context = {
        'mail_list': TemplateDataModel.objects.filter(user=request.user).order_by('id').reverse()
    }

    return render(request, 'user_site/email_data/index.html', context)


class UserEmailTemplateDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = TemplateDataModel
    success_message = 'Email Deleted Successfully'
    fields = '__all__'
    template_name = 'user_site/email_data/delete.html'
    context_object_name = "email"

    def get_success_url(self):
        return reverse("user_mails")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


def email_template_one_data_edit(request, pk):
    template_data = get_object_or_404(TemplateDataModel, pk=pk)
    if request.method == 'POST':
        title = request.POST.get('title')
        site_name = request.POST.get('site_name')
        logo = request.POST.get('logo')
        use_banner = 'use_banner' in request.POST
        banner_header = request.POST.get('banner_header')
        banner_description = request.POST.get('banner_description')
        body_intro = request.POST.get('body_intro')
        body_list = request.POST.get('body_list')
        body_list = [data.strip() for data in body_list.split('***')]
        body_conclusion = request.POST.get('body_conclusion')
        body_image = request.POST.get('body_image')
        body_image = [data.strip() for data in body_image.split(',')]
        footer_website = request.POST.get('footer_website')
        use_footer = 'use_footer' in request.POST

        dataset = {
            'title': title,
            'site_name': site_name,
            'logo': logo,
            'use_banner': use_banner,
            'banner_header': banner_header,
            'banner_description': banner_description,
            'body_intro': body_intro,
            'body_list': body_list,
            'body_conclusion': body_conclusion,
            'body_image': body_image,
            'footer_website': footer_website,
            'use_footer': use_footer
        }

        template_data.data = dataset
        template_data.save()
        if template_data.id:
            messages.success(request, 'Email Data Saved Successfully')
            return redirect(reverse('user_mails'))

    context = {
        'template_data': template_data
    }
    return render(request, 'user_site/email_data/template_1.html', context)


@login_required
def send_template_email(request, pk):
    if request.method == 'POST':
        smtp = request.POST.get('smtp')
        try:
            default_mail_account = SMTPConfigurationModel.objects.get(pk=smtp)
        except Exception:
            messages.error(request, 'An Error Occurred and Mail failed to send')
            return redirect(reverse('send_email'))

        subject = request.POST.get('subject')
        email_data = TemplateDataModel.objects.get(pk=pk)

        context = {
            'domain': get_current_site(request),
            'site_info': SiteInfoModel.objects.first(),
            'email_data': email_data
        }

        email_list = []
        email_string = request.POST.get('email')
        if email_string:
            email_string_list = email_string.split(",")
            for mail in email_string_list:
                email_list.append(mail.strip().lower())

        contact_list = request.POST.getlist('contact')
        email_list += contact_list

        mail_sent = 0
        for email in email_list:
            mail_sent = send_custom_email(
                subject=subject.upper(),
                recipient_list=[email],
                email_id=default_mail_account.id,
                template_name='user_site/email_template_send/{}.html'.format(email_data.template),
                context=context
            )

        if mail_sent > 0:
            messages.success(request, '{} Mail(s) sent successfully'.format(mail_sent))
            return redirect(reverse('send_template_email', kwargs={'pk': pk}))
        else:
            messages.warning(request, 'No mail sent, this may be due to wrong addresses provided')
            return redirect(reverse('send_template_email', kwargs={'pk': pk}))

    context = {
        'smtp_list': SMTPConfigurationModel.objects.filter(user=request.user).order_by(Lower('name')),
        'email_data': get_object_or_404(TemplateDataModel, pk=pk),
        'contact_list': ContactModel.objects.filter(user=request.user)
    }

    return render(request, 'user_site/mail/send.html', context)

