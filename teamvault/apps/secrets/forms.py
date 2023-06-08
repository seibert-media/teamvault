from datetime import date

from django import forms
from django.contrib.auth.models import Group, User
from django.forms.widgets import RadioSelect
from django.utils.translation import gettext_lazy as _

from .models import Secret

GENERIC_FIELDS_HEADER = ['name']
GENERIC_FIELDS_FOOTER = [
    'description',
    'access_policy',
    'needs_changing_on_leave',
    'allowed_groups',
    'allowed_users',
]


class SecretForm(forms.ModelForm):
    access_policy = forms.ChoiceField(
        choices=Secret.ACCESS_POLICY_CHOICES,
        initial=Secret.ACCESS_POLICY_DISCOVERABLE,
        widget=RadioSelect(),
    )
    allowed_groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all().order_by('name'),
        required=False,
    )
    allowed_users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('username'),
        required=False,
    )


class CCForm(SecretForm):
    expiration_month = forms.IntegerField(
        min_value=1,
        max_value=12,
    )
    expiration_year = forms.IntegerField(
        min_value=date.today().year,
        max_value=date.today().year + 50,
    )
    holder = forms.CharField(
        label=_('Name on card'),
    )
    number = forms.CharField()
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput,
    )
    security_code = forms.CharField(
        label=_('Card CVV'),
        required=False,
        widget=forms.NumberInput,
    )

    class Meta:
        model = Secret
        fields = (
            GENERIC_FIELDS_HEADER +
            [
                'expiration_month',
                'expiration_year',
                'holder',
                'number',
                'password',
                'security_code',
            ] +
            GENERIC_FIELDS_FOOTER
        )


class FileForm(SecretForm):
    file = forms.FileField(
        # Note: There's also custom handling for files with a file size above the FILE_UPLOAD_MAX_MEMORY_SIZE limit
        #  in the corresponding view
        allow_empty_file=False,
        help_text=_('This file will be stored securely.'),
        required=False,
    )

    class Meta:
        model = Secret
        fields = (
            GENERIC_FIELDS_HEADER +
            ['file'] +
            GENERIC_FIELDS_FOOTER
        )


class PasswordForm(SecretForm):
    password = forms.CharField(
        required=False,
    )
    url = forms.CharField(
        max_length=255,
        required=False,
        label='URL',
        help_text=_('This field will also be considered when searching.')
    )
    username = forms.CharField(
        max_length=255,
        required=False,
        help_text=_('This field will also be considered when searching.')
    )

    def clean_password(self):
        if self.instance.pk is None and not self.cleaned_data['password']:
            # password is only required when adding a new secret
            raise forms.ValidationError(_("Please enter a password."))
        return self.cleaned_data['password']

    class Meta:
        model = Secret
        fields = (
            GENERIC_FIELDS_HEADER +
            ['password', 'username', 'url'] +
            GENERIC_FIELDS_FOOTER
        )
