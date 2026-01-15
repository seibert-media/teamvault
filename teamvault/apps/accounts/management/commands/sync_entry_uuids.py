from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from django_auth_ldap.config import LDAPSearch

User = get_user_model()


def _get_attr(attrs, key):
    if key in attrs:
        values = attrs[key]
    elif isinstance(key, str) and key.encode() in attrs:
        values = attrs[key.encode()]
    else:
        return None
    if not values:
        return None
    value = values[0]
    return value.decode() if isinstance(value, bytes) else value


class Command(BaseCommand):
    help = 'Sets User.entry_uuid for users that do not have one yet.'

    def handle(self, *args, **options):  # noqa: ARG002
        if not getattr(settings, 'LDAP_AUTH_ENABLED', False):
            self.stderr.write('LDAP auth is not enabled.')
            return

        if not getattr(settings, 'AUTH_LDAP_SERVER_URI', None):
            self.stderr.write('Missing AUTH_LDAP_SERVER_URI in settings.')
            return

        entry_uuid_attr = settings.AUTH_LDAP_USER_ATTR_MAP.get('entry_uuid', 'entryUUID')
        search = LDAPSearch(
            settings.AUTH_LDAP_USER_SEARCH.base_dn,
            settings.AUTH_LDAP_USER_SEARCH.scope,
            settings.AUTH_LDAP_USER_SEARCH.filterstr,
            [entry_uuid_attr],
        )

        connection = _LDAPUser(LDAPBackend(), username='').connection

        users = User.objects.filter(entry_uuid='')
        self.stdout.write(f'Checking {users.count()} users without entry_uuid...')

        updated = 0
        for user in users:
            results = search.execute(connection, filterargs={'user': user.username})
            if not results:
                continue
            _dn, attrs = results[0]
            entry_uuid = _get_attr(attrs, entry_uuid_attr)
            if not entry_uuid:
                continue
            user.entry_uuid = entry_uuid
            user.save(update_fields=['entry_uuid'])
            updated += 1
            self.stdout.write(f'{user.username}: set entry_uuid {entry_uuid}')

        connection.unbind_s()
        self.stdout.write(self.style.SUCCESS(f'Done. Updated {updated} users.'))
