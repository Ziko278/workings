from django.urls import path
from admin_site.views import *

urlpatterns = [
    path('', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('login', admin_sign_in_view, name='admin_login'),
    path('logout', admin_sign_out_view, name='admin_logout'),
    
    path('site-info/create', SiteInfoCreateView.as_view(), name='site_info_create'),
    path('site-info/<int:pk>/detail', SiteInfoDetailView.as_view(), name='site_info_detail'),
    path('site-info/<int:pk>/edit', SiteInfoUpdateView.as_view(), name='site_info_edit'),

    path('site-setting/create', SiteSettingCreateView.as_view(), name='site_setting_create'),
    path('site-setting/<int:pk>/detail', SiteSettingDetailView.as_view(), name='site_setting_detail'),
    path('site-setting/<int:pk>/edit', SiteSettingUpdateView.as_view(), name='site_setting_edit'),

    path('index', UserListView.as_view(), name='admin_user_index'),
    path('<int:pk>/detail', UserDetailView.as_view(), name='admin_user_detail'),
    path('<int:pk>/delete', UserDeleteView.as_view(), name='admin_user_delete'),

    path('dashboard', UserDashboardView.as_view(), name='admin_user_dashboard'),

    path('funding/<str:funding>/index', FundingListView.as_view(), name='funding_index'),

]

