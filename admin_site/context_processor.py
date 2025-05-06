from django.db.models import F

from admin_site.models import SiteInfoModel, SiteSettingModel
from django.contrib.auth.models import AnonymousUser
from django.shortcuts import redirect


def general_info(request):

    return {
        'site_info': SiteInfoModel.objects.first(),
        'site_setting': SiteSettingModel.objects.first(),
    }
