from datetime import date

from django import forms
from django.contrib.auth.models import Group, User
from django.core.exceptions import ValidationError
from django.forms.widgets import RadioSelect
from django.utils.translation import gettext_lazy as _

from .models import Secret, SharedSecretData

GENERIC_FIELDS_HEADER = ['name']
GENERIC_FIELDS_FOOTER = [
    'description',
    'access_policy',
    'needs_changing_on_leave',
]


class SecretForm(forms.ModelForm):
    access_policy = forms.ChoiceField(
        choices=Secret.ACCESS_POLICY_CHOICES,
        initial=Secret.ACCESS_POLICY_DISCOVERABLE,
        widget=RadioSelect(),
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


class SecretShareForm(forms.ModelForm):
    group = forms.ModelChoiceField(
        required=False,
        queryset=Group.objects.all().order_by('name'),
    )

    user = forms.ModelChoiceField(
        required=False,
        queryset=User.objects.filter(is_active=True).order_by('username'),
    )

    grant_description = forms.CharField(
        label=_('Reason'),
        required=False,
        widget=forms.Textarea(attrs={'cols': '15', 'rows': '1', 'placeholder': _('(optional)')})
    )

    granted_until = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(),
    )

    def clean(self):
        cleaned_data = super().clean()
        if (cleaned_data['group'] and cleaned_data['user']) or (not cleaned_data['group'] and not cleaned_data['user']):
            raise ValidationError('Choose exactly one group *or* one user to share the secret with.')

    class Meta:
        fields = ['group', 'user', 'granted_until', 'grant_description']
        model = SharedSecretData
