from django import forms

from teamvault.apps.accounts.models import UserProfile


class UserProfileForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['default_sharing_groups'].queryset = self.fields['default_sharing_groups'].queryset.order_by('name')

    class Meta:
        fields = ['default_sharing_groups', 'hide_deleted_secrets']
        model = UserProfile
