from django import forms
from django.utils.translation import gettext_lazy as _

from teamvault.apps.accounts.models import UserProfile, UserToken


class UserProfileForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['default_sharing_groups'].queryset = self.fields['default_sharing_groups'].queryset.order_by('name')

    class Meta:
        fields = ['default_sharing_groups', 'hide_deleted_secrets']
        model = UserProfile


class UserTokenForm(forms.ModelForm):
    key = forms.CharField(
        disabled=True,
        required=False,
        widget=forms.TextInput(attrs={'placeholder': _('A secure key will be generated automatically.')})
    )

    class Meta:
        fields = ['key', 'label', 'expires', 'write_enabled']
        model = UserToken
