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

        # Defensive: configure_ldap_auth sets attrlist, but guard against downstream patches.
        entry_uuid_attr = getattr(settings, 'AUTH_LDAP_GROUP_ENTRY_UUID_ATTR', 'entryUUID')
        group_search = getattr(settings, 'AUTH_LDAP_GROUP_SEARCH', None)
        if group_search is not None:
            if group_search.attrlist is None:
                group_search.attrlist = ['*', entry_uuid_attr]
            elif entry_uuid_attr not in group_search.attrlist:
                group_search.attrlist.append(entry_uuid_attr)

        populate_user.connect(sync_group_uuids_before_mirror)
