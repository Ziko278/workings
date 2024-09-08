from django.contrib.auth.forms import UserCreationForm
from django.forms import ModelForm, Select, TextInput, Textarea, CheckboxSelectMultiple, DateInput
from django.contrib.auth.models import User
from django import forms
from django.core.exceptions import ValidationError
from admin_site.models import *


class SiteInfoForm(ModelForm):
    """"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields[field].widget.attrs.update({
                'class': 'form-control',
                'autocomplete': 'off'
            })

    class Meta:
        model = SiteInfoModel
        fields = '__all__'
        widgets = {

        }


class SiteSettingForm(ModelForm):
    """"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields:
            if field not in ['email_confirmation', 'referral_payment_before_bonus', 'trade_termination']:
                self.fields[field].widget.attrs.update({
                    'class': 'form-control',
                    'autocomplete': 'off'
                })

    class Meta:
        model = SiteSettingModel
        fields = '__all__'
        widgets = {

        }


class MediaForm(ModelForm):
    """"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields[field].widget.attrs.update({
                'class': 'form-control',
                'autocomplete': 'off'
            })

    class Meta:
        model = MediaModel
        fields = '__all__'
        widgets = {

        }
