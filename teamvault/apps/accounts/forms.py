from django import forms

from teamvault.apps.accounts.models import UserSettings


class UserSettingsForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['default_sharing_groups'].queryset = self.fields['default_sharing_groups'].queryset.order_by('name')

    class Meta:
        fields = ['default_sharing_groups']
        model = UserSettings
