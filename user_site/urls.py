from django.urls import path
from user_site.views import *
from django.views.generic import TemplateView

urlpatterns = [
    path('register', user_signup_view, name='register'),
    path('login', user_signin_view, name='login'),
    path('change-password', user_change_password_view, name='user_change_password'),
    path('logout', user_sign_out_view, name='logout'),

    path('password_reset/', password_reset_request, name='user_password_reset'),
    path('reset/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('password_reset/done/', TemplateView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/done/', TemplateView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),

    path('profile/email-verification', email_verification_one, name='email_verify_1'),
    path('profile/send-verification-email', email_verification_two, name='email_verify_2'),

    path('', UserDashboardView.as_view(), name='user_dashboard'),
    path('referrals', UserReferralView.as_view(), name='user_referral'),
    path('profile', UserProfileView.as_view(), name='user_profile'),
    path('profile/verification', UserProfileVerificationView.as_view(), name='user_profile_verification'),
    path('profile/<int:pk>/edit', UserProfileChangeView.as_view(), name='user_profile_edit'),

    path('funding/index', UserFundingListView.as_view(), name='user_funding_index'),

    path('media/create', MediaCreateView.as_view(), name='user_media_create'),
    path('media/index', MediaListView.as_view(), name='user_media_index'),
    path('media/<int:pk>/update', MediaUpdateView.as_view(), name='user_media_update'),
    path('media/<int:pk>/delete', MediaDeleteView.as_view(), name='user_media_delete'),
    
    path('contact/create', ContactCreateView.as_view(), name='user_contact_create'),
    path('contact/index', ContactListView.as_view(), name='user_contact_index'),
    path('contact/<int:pk>/update', ContactUpdateView.as_view(), name='user_contact_update'),
    path('contact/<int:pk>/delete', ContactDeleteView.as_view(), name='user_contact_delete'),

    path('smtp-configuration/create', SMTPConfigurationCreateView.as_view(), name='smtp_configuration_create'),
    path('smtp-configuration/index', SMTPConfigurationListView.as_view(), name='smtp_configuration_index'),
    path('smtp-configuration/<int:pk>/edit', SMTPConfigurationUpdateView.as_view(), name='smtp_configuration_edit'),
    path('smtp-configuration/<int:pk>/delete', SMTPConfigurationDeleteView.as_view(), name='smtp_configuration_delete'),

    path('email-templates', UserEmailTemplateView.as_view(), name='user_email_template_view'),
    path('plain-multimedia-mail', email_template_one_data, name='email_template_one_data'),
    path('plain-multimedia-mail-2', email_template_two_data, name='email_template_two_data'),
    path('plain-multimedia-mail/<int:pk>/edit', email_template_one_data_edit, name='email_template_one_data_edit'),
    path('mails', user_mails, name='user_mails'),
    path('mails/<int:pk>/delete', UserEmailTemplateDeleteView.as_view(), name='user_mail_delete'),
    path('mails/<int:pk>/send', send_template_email, name='send_template_email'),
]

