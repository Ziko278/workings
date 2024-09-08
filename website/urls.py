from django.urls import path
from website.views import *

urlpatterns = [
    path('', HomePageView.as_view(), name='homepage'),

   ]

