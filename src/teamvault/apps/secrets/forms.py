from datetime import date
from json import dumps

from django import forms
from django.contrib.auth.models import Group, User
from django.forms.widgets import SelectMultiple
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _

from .models import Secret


GENERIC_FIELDS_HEADER = ['name']
GENERIC_FIELDS_FOOTER = [
    'description',
    'access_policy',
    'needs_changing_on_leave',
    'allowed_groups',
    'allowed_users',
    'owner_groups',
    'owner_users',
]


class Select2DataWidget(SelectMultiple):
    """
    Used to render form values as a select2-compatible data structure.
    """
    def render(self, name, value, attrs=None, choices=()):
        if value is None:
            return "[]"
        output = []
        value_ints = [int(v) for v in value]
        for option_id, option_label in self.choices:
            if option_id in value_ints:
                output.append({'id': str(option_id), 'text': option_label})
        return mark_safe(dumps(output))


class SecretForm(forms.ModelForm):
    allowed_groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        widget=Select2DataWidget,
    )
    allowed_users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=Select2DataWidget,
    )
    owner_groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        widget=Select2DataWidget,
    )
    owner_users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=Select2DataWidget,
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
    holder = forms.CharField()
    number = forms.CharField()
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput,
    )
    security_code = forms.IntegerField(
        required=False,
        min_value=100,
        max_value=9999,
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
    password = forms.CharField(
        required=False,
    )
    url = forms.CharField(
        max_length=255,
        required=False,
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

    class Meta:
        model = Secret
        fields = (
            GENERIC_FIELDS_HEADER +
            ['password', 'username', 'url'] +
            GENERIC_FIELDS_FOOTER
        )
