from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django_auth_ldap.config import LDAPSearch
from teamvault.apps.accounts.backends import _get_attr, _get_ldap_connection
from teamvault.apps.accounts.management.commands._ldap_sync import ldap_sync_enabled

User = get_user_model()


class Command(BaseCommand):
    help = 'Sets User.ldap_uuid for users that do not have one yet.'

    def handle(self, *args, **options):  # noqa: ARG002
        if not ldap_sync_enabled(self):
            return

        ldap_uuid_attr = settings.AUTH_LDAP_USER_ATTR_MAP.get('ldap_uuid', 'entryUUID')
        search = LDAPSearch(
            settings.AUTH_LDAP_USER_SEARCH.base_dn,
            settings.AUTH_LDAP_USER_SEARCH.scope,
            settings.AUTH_LDAP_USER_SEARCH.filterstr,
            [ldap_uuid_attr],
        )

        connection = _get_ldap_connection()

        users = User.objects.filter(ldap_uuid='')
        self.stdout.write(f'Checking {users.count()} users without ldap_uuid...')

        updated = 0
        for user in users:
            results = search.execute(connection, filterargs={'user': user.username})
            if not results:
                continue
            _dn, attrs = results[0]
            ldap_uuid = _get_attr(attrs, ldap_uuid_attr)
            if not ldap_uuid:
                continue
            user.ldap_uuid = ldap_uuid
            user.save(update_fields=['ldap_uuid'])
            updated += 1
            self.stdout.write(f'{user.username}: set ldap_uuid {ldap_uuid}')

        connection.unbind_s()
        self.stdout.write(self.style.SUCCESS(f'Done. Updated {updated} users.'))
