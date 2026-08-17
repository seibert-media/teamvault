from django.conf import settings
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from teamvault.apps.accounts.backends import _get_ldap_connection
from teamvault.apps.accounts.ldap_uuid import canonicalize_ldap_uuid
from teamvault.apps.accounts.management.commands._ldap_sync import ldap_sync_enabled
from teamvault.apps.accounts.models import GroupUUIDMapping


class Command(BaseCommand):
    help = 'Sets GroupUUIDMapping.ldap_uuid for existing groups based on LDAP data.'

    def handle(self, *args, **options):  # noqa: ARG002
        if not ldap_sync_enabled(self):
            return

        ldap_uuid_attr: str | None = getattr(settings, 'AUTH_LDAP_GROUP_UUID_ATTR', None)
        if not ldap_uuid_attr:
            self.stderr.write('attr_group_uuid is not configured; nothing to do.')
            return

        # configure_ldap_auth already adds ldap_uuid_attr to the search attrlist when the feature is enabled
        search = settings.AUTH_LDAP_GROUP_SEARCH
        group_type = settings.AUTH_LDAP_GROUP_TYPE

        connection = _get_ldap_connection()

        self.stdout.write('Fetching all LDAP groups...')
        results = search.execute(connection)
        connection.unbind_s()

        ldap_map = {}
        ambiguous_names = set()
        for group_info in results:
            _dn, attrs = group_info
            name = group_type.group_name_from_info(group_info)
            raw = attrs.get(ldap_uuid_attr) or attrs.get(ldap_uuid_attr.encode())
            if not (name and raw):
                continue
            ldap_uuid = canonicalize_ldap_uuid(raw[0])
            if ldap_uuid is None:
                self.stderr.write(f'LDAP group "{name}" has an unusable {ldap_uuid_attr} value; skipping it.')
                continue
            if name in ldap_map:
                ambiguous_names.add(name)
                continue
            ldap_map[name] = ldap_uuid

        for name in ambiguous_names:
            # matching is name-based here, so an ambiguous name could bind a Django
            # group to the wrong UUID permanently (ldap_uuid is unique, never corrected)
            del ldap_map[name]
            self.stderr.write(f'Skipping LDAP group name "{name}": multiple LDAP groups share it.')

        self.stdout.write(f'Loaded {len(ldap_map)} LDAP groups.')

        groups_without_mapping = Group.objects.filter(uuid_mapping__isnull=True)

        mappings_to_create = []
        for group in groups_without_mapping:
            ldap_uuid = ldap_map.get(group.name)
            if ldap_uuid:
                mappings_to_create.append(GroupUUIDMapping(group=group, ldap_uuid=ldap_uuid))
                self.stdout.write(f'{group.name}: set ldap_uuid {ldap_uuid}')

        if mappings_to_create:
            GroupUUIDMapping.objects.bulk_create(mappings_to_create, ignore_conflicts=True)

        self.stdout.write(self.style.SUCCESS(f'Done. Created {len(mappings_to_create)} mappings.'))
