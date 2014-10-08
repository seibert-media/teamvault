from datetime import date

from django import forms

from .models import Secret


GENERIC_FIELDS_HEADER = ['name']
GENERIC_FIELDS_FOOTER = [
    'description',
    'access_policy',
    'needs_changing_on_leave',
    'allowed_groups',
    'allowed_users',
]


class AddCCForm(forms.ModelForm):
    expiration_month = forms.IntegerField(
        min_value=1,
        max_value=12,
    )
    expiration_year = forms.IntegerField(
        min_value=date.today().year,
        max_value=date.today().year + 50,
    )
    holder = forms.CharField()
    number = forms.IntegerField(
        widget=forms.TextInput,
    )
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput,
    )
    security_code = forms.IntegerField(
        required=False,
        min_value=100,
        max_value=9999,
    )


class AddFileForm(forms.ModelForm):
    file = forms.FileField(
        allow_empty_file=False,
    )


class AddPasswordForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput,
    )
    url = forms.URLField(
        required=False,
    )
    username = forms.CharField(
        required=False,
    )
    class Meta:
        model = Secret
        fields = (
            GENERIC_FIELDS_HEADER +
            ['password', 'username', 'url'] +
            GENERIC_FIELDS_FOOTER
        )
