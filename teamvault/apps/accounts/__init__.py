from typing import override

from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = 'teamvault.apps.accounts'

    @override
    def ready(self):
        from django.conf import settings

        if not getattr(settings, 'LDAP_AUTH_ENABLED', False):
            return
        if not getattr(settings, 'AUTH_LDAP_AUTO_RENAME_GROUPS', False):
            return

        from django_auth_ldap.backend import populate_user

        from teamvault.apps.accounts.signals import sync_group_uuids_before_mirror

        populate_user.connect(
            sync_group_uuids_before_mirror,
            dispatch_uid='teamvault.accounts.sync_group_uuids_before_mirror',
        )
