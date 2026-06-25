from django.conf import settings
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from django_auth_ldap.config import LDAPSearch
from teamvault.apps.accounts.backends import _get_attr, _get_ldap_connection
from teamvault.apps.accounts.models import GroupUUIDMapping


class Command(BaseCommand):
    help = 'Sets GroupUUIDMapping.entry_uuid for existing groups based on LDAP data.'

    def handle(self, *args, **options):  # noqa: ARG002
        if not getattr(settings, 'LDAP_AUTH_ENABLED', False):
            self.stderr.write('LDAP auth is not enabled.')
            return

        if not getattr(settings, 'AUTH_LDAP_SERVER_URI', None):
            self.stderr.write('Missing AUTH_LDAP_SERVER_URI in settings.')
            return

        entry_uuid_attr = getattr(settings, 'AUTH_LDAP_GROUP_ENTRY_UUID_ATTR', None)
        if not entry_uuid_attr:
            self.stderr.write('attr_group_entry_uuid is not configured; nothing to do.')
            return
        base_search = settings.AUTH_LDAP_GROUP_SEARCH
        search = LDAPSearch(
            base_search.base_dn,
            base_search.scope,
            base_search.filterstr,
            ['*', entry_uuid_attr],
        )
        group_type = settings.AUTH_LDAP_GROUP_TYPE

        connection = _get_ldap_connection()

        self.stdout.write('Fetching all LDAP groups...')
        results = search.execute(connection)
        connection.unbind_s()

        ldap_map = {}
        for group_info in results:
            _dn, attrs = group_info
            name = group_type.group_name_from_info(group_info)
            entry_uuid = _get_attr(attrs, entry_uuid_attr)
            if name and entry_uuid:
                ldap_map[name] = entry_uuid

        self.stdout.write(f'Loaded {len(ldap_map)} LDAP groups.')

        groups_without_mapping = Group.objects.filter(uuid_mapping__isnull=True)

        mappings_to_create = []
        for group in groups_without_mapping:
            entry_uuid = ldap_map.get(group.name)
            if entry_uuid:
                mappings_to_create.append(GroupUUIDMapping(group=group, entry_uuid=entry_uuid))
                self.stdout.write(f'{group.name}: set entry_uuid {entry_uuid}')

        if mappings_to_create:
            GroupUUIDMapping.objects.bulk_create(mappings_to_create, ignore_conflicts=True)

        self.stdout.write(self.style.SUCCESS(f'Done. Created {len(mappings_to_create)} mappings.'))
