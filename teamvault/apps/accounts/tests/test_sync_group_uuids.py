import uuid
from io import StringIO
from unittest.mock import Mock, patch

import ldap
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import TestCase, override_settings
from django_auth_ldap.config import GroupOfNamesType, LDAPSearch

from teamvault.apps.accounts.models import GroupUUIDMapping

GUID = uuid.UUID('12345678-1234-5678-9abc-123456789abc')


def info(name, ldap_uuid):
    dn = f'cn={name},ou=Groups,dc=test'
    return dn, {'cn': [name], 'entryUUID': [ldap_uuid]}


@override_settings(
    LDAP_AUTH_ENABLED=True,
    AUTH_LDAP_SERVER_URI='ldap://ldap.test',
    AUTH_LDAP_GROUP_UUID_ATTR='entryUUID',
    AUTH_LDAP_GROUP_SEARCH=LDAPSearch('ou=groups,dc=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
    AUTH_LDAP_GROUP_TYPE=GroupOfNamesType(),
)
class SyncGroupEntryUUIDsCommandTests(TestCase):
    @staticmethod
    def _call(group_infos):
        connection = Mock()
        connection.search_s.return_value = group_infos
        stdout, stderr = StringIO(), StringIO()
        with patch(
            'teamvault.apps.accounts.management.commands.sync_group_uuids._get_ldap_connection',
            return_value=connection,
        ):
            call_command('sync_group_uuids', stdout=stdout, stderr=stderr)
        return stdout.getvalue(), stderr.getvalue()

    def test_creates_mapping_for_unmapped_group(self):
        group = Group.objects.create(name='engineering')

        self._call([info('engineering', 'uuid-eng')])

        self.assertEqual(GroupUUIDMapping.objects.get(group=group).ldap_uuid, 'uuid-eng')

    def test_skips_ambiguous_ldap_names(self):
        Group.objects.create(name='dup')

        _stdout, stderr = self._call([info('dup', 'uuid-1'), info('dup', 'uuid-2')])

        self.assertFalse(GroupUUIDMapping.objects.exists())
        self.assertIn('dup', stderr)

    def test_canonicalizes_binary_guid(self):
        group = Group.objects.create(name='ad-team')

        self._call([('cn=ad-team,ou=Groups,dc=test', {'cn': ['ad-team'], 'entryUUID': [GUID.bytes_le]})])

        self.assertEqual(GroupUUIDMapping.objects.get(group=group).ldap_uuid, str(GUID))

    def test_skips_unusable_uuid_values(self):
        Group.objects.create(name='broken')

        _stdout, stderr = self._call([('cn=broken,ou=Groups,dc=test', {'cn': ['broken'], 'entryUUID': [b'\xff\xfe']})])

        self.assertFalse(GroupUUIDMapping.objects.exists())
        self.assertIn('broken', stderr)
