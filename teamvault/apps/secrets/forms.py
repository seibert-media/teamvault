from datetime import date

from django import forms
from django.contrib.auth.models import Group, User
from django.core.exceptions import ValidationError
from django.forms.widgets import RadioSelect
from django.utils.translation import gettext_lazy as _

from .models import Secret, SharedSecretData
from .utils import extract_url_and_params
from .validators import is_valid_otp_secret

GENERIC_FIELDS_HEADER = ['name']
GENERIC_FIELDS_FOOTER = [
    'access_policy',
    'description',
    'grant_description',
    'needs_changing_on_leave',
    'shared_groups_on_create',
]


class SecretForm(forms.ModelForm):
    access_policy = forms.ChoiceField(
        choices=Secret.ACCESS_POLICY_CHOICES,
        initial=Secret.ACCESS_POLICY_DISCOVERABLE,
        widget=RadioSelect(),
    )
    description = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'cols': '15', 'rows': '4'})
    )
    needs_changing_on_leave = forms.BooleanField(
        help_text=_("This secret will be marked as 'needs changing' when a user who accessed it is deactivated."),
        initial=True,
        label=_('Needs changing'),
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    shared_groups_on_create = forms.ModelMultipleChoiceField(
        help_text=_('Default groups you configured in your settings will be selected automatically.'),
        label=_('Share with groups'),
        queryset=Group.objects.all().order_by('name'),
        required=False,
    )
    grant_description = forms.CharField(
        label=_('Reason'),
        required=False,  # see clean() below
        widget=forms.Textarea(attrs={'cols': '15', 'rows': '2'}),
    )

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data['shared_groups_on_create'] and not cleaned_data['grant_description']:
            self.add_error(
                'grant_description',
                _('Please provide a valid reason to share this secret with the groups selected above.')
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
    otp_key = forms.CharField(
        required=False
    )
    otp_key_data = forms.CharField(
        required=False,
    )
    password = forms.CharField(
        required=False,
    )
    url = forms.CharField(
        max_length=255,
        required=False,
        label='URL',
    )
    username = forms.CharField(
        max_length=255,
        required=False,
    )

    def clean_password(self):
        if self.instance.pk is None and not self.cleaned_data['password']:
            # password is only required when adding a new secret
            raise forms.ValidationError(_("Please enter a password."))
        return self.cleaned_data['password']

    def clean_otp_key_data(self):
        cleaned_otp_key_data = self.cleaned_data['otp_key_data']
        if self.instance.pk is not None and not cleaned_otp_key_data:
            return cleaned_otp_key_data

        try:
            as_url, data_params = extract_url_and_params(cleaned_otp_key_data)
        except Exception:
            raise forms.ValidationError(_('OTP key should have a format like this: ___?secret=___&digits=___ ...'))
        secret = data_params['secret'] if 'secret' in data_params else ''
        is_valid_otp_secret(secret)
        return cleaned_otp_key_data

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
        queryset=Group.objects.none(),  # will be set in view
    )

    user = forms.ModelChoiceField(
        required=False,
        queryset=User.objects.none(),  # will be set in view
    )

    grant_description = forms.CharField(
        label=_('Reason'),
        required=True,
        widget=forms.Textarea(attrs={'cols': '15', 'rows': '2'})
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
