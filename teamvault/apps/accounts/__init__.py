from typing import override

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = 'teamvault.apps.accounts'

    @override
    def ready(self):
        from django_auth_ldap.backend import populate_user

        from teamvault.apps.accounts.signals import sync_group_uuids_before_mirror

        # Connect unconditionally: this runs before SettingsConfig.ready() has injected the
        # LDAP settings, so feature toggles cannot be checked here. The receiver guards itself.
        populate_user.connect(
            sync_group_uuids_before_mirror,
            dispatch_uid='teamvault.accounts.sync_group_uuids_before_mirror',
        )
