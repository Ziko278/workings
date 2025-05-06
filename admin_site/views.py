import json

from django.contrib.auth import authenticate, login, logout
from django.db.models import Sum
from django.db.models.functions import Lower
from django.views.generic import TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.http import HttpResponse, HttpRequest
from django.urls import reverse
# from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.contrib.messages.views import SuccessMessageMixin, messages
from django.views.generic import TemplateView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from admin_site.forms import SiteInfoForm, SiteSettingForm, MediaForm
from admin_site.models import SiteInfoModel, SiteSettingModel, MediaModel
from datetime import date, datetime, timedelta
from user_site.models import UserFundingModel, UserWalletModel, UserProfileModel


class AdminDashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'admin_site/dashboard.html'

    def dispatch(self, *args, **kwargs):
        if not self.request.user.is_authenticated:
            return redirect(reverse('admin_login'))
        return super(AdminDashboardView, self).dispatch(*args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_user'] = UserProfileModel.objects.count()

        return context


class SiteInfoCreateView(LoginRequiredMixin, PermissionRequiredMixin, CreateView):
    model = SiteInfoModel
    form_class = SiteInfoForm
    permission_required = 'admin_site.change_siteinfomodel'
    success_message = 'Site Information Updated Successfully'
    template_name = 'admin_site/site_info/create.html'

    def dispatch(self, *args, **kwargs):
        site_info = SiteInfoModel.objects.first()
        if not site_info:
            return super(SiteInfoCreateView, self).dispatch(*args, **kwargs)
        else:
            return redirect(reverse('site_info_edit', kwargs={'pk': site_info.pk}))

    def get_success_url(self):
        return reverse('site_info_detail', kwargs={'pk': self.object.pk})

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class SiteInfoDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    model = SiteInfoModel
    permission_required = 'admin_site.view_siteinfomodel'
    fields = '__all__'
    template_name = 'admin_site/site_info/detail.html'
    context_object_name = "site_info"

    def dispatch(self, *args, **kwargs):
        site_info = SiteInfoModel.objects.first()
        if site_info:
            if self.kwargs.get('pk') != site_info.id:
                return redirect(reverse('site_info_detail', kwargs={'pk': site_info.pk}))
            return super(SiteInfoDetailView, self).dispatch(*args, **kwargs)
        else:
            return redirect(reverse('site_info_create'))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        return context


class SiteInfoUpdateView(LoginRequiredMixin, PermissionRequiredMixin, SuccessMessageMixin, UpdateView):
    model = SiteInfoModel
    permission_required = 'admin_site.change_siteinfomodel'
    form_class = SiteInfoForm
    success_message = 'Site Information Updated Successfully'
    template_name = 'admin_site/site_info/create.html'

    def get_success_url(self):
        return reverse('site_info_detail', kwargs={'pk': self.object.pk})

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['site_info'] = self.object
        return context


class SiteSettingCreateView(LoginRequiredMixin, PermissionRequiredMixin, CreateView):
    model = SiteSettingModel
    form_class = SiteSettingForm
    permission_required = 'admin_site.change_sitesettingmodel'
    success_message = 'Site Setting Updated Successfully'
    template_name = 'admin_site/site_setting/create.html'

    def dispatch(self, *args, **kwargs):
        site_info = SiteSettingModel.objects.first()
        if not site_info:
            return super(SiteSettingCreateView, self).dispatch(*args, **kwargs)
        else:
            return redirect(reverse('site_setting_edit', kwargs={'pk': site_info.pk}))

    def get_success_url(self):
        return reverse('site_setting_detail', kwargs={'pk': self.object.pk})

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class SiteSettingDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    model = SiteSettingModel
    permission_required = 'admin_site.change_sitesettingmodel'
    fields = '__all__'
    template_name = 'admin_site/site_setting/detail.html'
    context_object_name = "site_setting"

    def dispatch(self, *args, **kwargs):
        site_info = SiteSettingModel.objects.first()
        if site_info:
            if self.kwargs.get('pk') != site_info.id:
                return redirect(reverse('site_setting_detail', kwargs={'pk': site_info.pk}))
            return super(SiteSettingDetailView, self).dispatch(*args, **kwargs)
        else:
            return redirect(reverse('site_setting_create'))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        return context


class SiteSettingUpdateView(LoginRequiredMixin, PermissionRequiredMixin, SuccessMessageMixin, UpdateView):
    model = SiteSettingModel
    form_class = SiteSettingForm
    permission_required = 'admin_site.change_sitesettingmodel'
    success_message = 'Site Setting Updated Successfully'
    template_name = 'admin_site/site_setting/create.html'

    def get_success_url(self):
        return reverse('site_setting_detail', kwargs={'pk': self.object.pk})

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['site_setting'] = self.object
        return context


class FundingListView(LoginRequiredMixin, TemplateView):
    template_name = 'admin_site/funding/index.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['funding_list'] = UserFundingModel.objects.all().order_by('id').reverse()
        return context


def admin_sign_in_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            intended_route = request.POST.get('next') or request.GET.get('next')
            remember_me = request.POST.get('remember_me') or request.GET.get('remember_me')

            if user.is_superuser:
                login(request, user)
                messages.success(request, 'welcome back {}'.format(user.username.title()))
                if remember_me:
                    request.session.set_expiry(3600 * 24 * 30)
                else:
                    request.session.set_expiry(0)
                if intended_route:
                    return redirect(intended_route)
                return redirect(reverse('admin_dashboard'))

            else:
                messages.error(request, 'Unknown Identity, Access Denied')
                return redirect(reverse('login'))
        else:
            messages.error(request, 'Invalid Credentials')
            return redirect(reverse('admin_login'))

    return render(request, 'admin_site/sign_in.html')


def admin_sign_out_view(request):
    logout(request)
    return redirect(reverse('admin_login'))


class UserListView(LoginRequiredMixin, ListView):
    model = User
    fields = '__all__'
    template_name = 'user_management/user/index.html'
    context_object_name = "user_list"

    def get_queryset(self):
        return User.objects.filter(is_superuser=False).order_by(Lower('username'))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class UserDetailView(LoginRequiredMixin, DetailView):
    model = User
    fields = '__all__'
    template_name = 'user_management/user/detail.html'
    context_object_name = "client"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        return context


class UserDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = User
    success_message = 'User Deleted Successfully'
    template_name = 'user_management/user/delete.html'
    context_object_name = "client"

    def get_success_url(self):
        return reverse('admin_user_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class UserDashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'user_management/user/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_users'] = UserProfileModel.objects.all().count()
        return context


class MediaCreateView(LoginRequiredMixin, SuccessMessageMixin, CreateView):
    model = MediaModel
    form_class = MediaForm
    success_message = 'Media Added Successfully'
    template_name = 'admin_site/media/index.html'

    def get_success_url(self):
        return reverse('admin_media_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['media_list'] = MediaModel.objects.all().order_by('name')
        return context


class MediaListView(LoginRequiredMixin, ListView):
    model = MediaModel
    fields = '__all__'
    template_name = 'admin_site/media/index.html'
    context_object_name = "media_list"

    def get_queryset(self):
        return MediaModel.objects.all().order_by('name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['form'] = MediaForm
        return context


class MediaUpdateView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    model = MediaModel
    form_class = MediaForm
    success_message = 'Media Updated Successfully'
    template_name = 'admin_site/media/index.html'

    def get_success_url(self):
        return reverse('admin_media_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['media_list'] = MediaModel.objects.all().order_by('name')
        return context


class MediaDeleteView(LoginRequiredMixin, SuccessMessageMixin, DeleteView):
    model = MediaModel
    success_message = 'Media Deleted Successfully'
    fields = '__all__'
    template_name = 'admin_site/media/delete.html'
    context_object_name = "media"

    def get_success_url(self):
        return reverse('admin_media_index')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context
