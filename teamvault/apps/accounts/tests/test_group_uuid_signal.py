from types import SimpleNamespace
from unittest.mock import Mock

from django.contrib.auth.models import Group
from django.test import TestCase
from django_auth_ldap.config import GroupOfNamesType

from teamvault.apps.accounts.models import GroupUUIDMapping
from teamvault.apps.accounts.signals import sync_group_uuids_before_mirror


def fake_ldap_user(group_infos):
    """Build the minimal duck-typed `ldap_user` shape the signal touches."""
    groups = SimpleNamespace(
        _get_group_infos=lambda: group_infos,
        _group_type=GroupOfNamesType(),
    )
    return SimpleNamespace(_get_groups=lambda: groups)


def info(name, entry_uuid):
    dn = f'cn={name},ou=Groups,dc=test'
    return dn, {'cn': [name], 'entryUUID': [entry_uuid]}


class SyncGroupUUIDsBeforeMirrorTests(TestCase):
    @staticmethod
    def _fire(group_infos):
        sync_group_uuids_before_mirror(sender=Mock(), user=Mock(), ldap_user=fake_ldap_user(group_infos))

    def test_noop_when_ldap_returns_no_groups(self):
        self._fire([])

        self.assertFalse(GroupUUIDMapping.objects.exists())
        self.assertFalse(Group.objects.exists())

    def test_creates_group_and_mapping_for_unknown_uuid(self):
        self._fire([info('engineering', 'uuid-eng')])

        group = Group.objects.get(name='engineering')
        mapping = GroupUUIDMapping.objects.get(entry_uuid='uuid-eng')
        self.assertEqual(mapping.group, group)

    def test_renames_group_when_ldap_name_changes(self):
        group = Group.objects.create(name='old-name')
        GroupUUIDMapping.objects.create(group=group, entry_uuid='uuid-1')

        self._fire([info('new-name', 'uuid-1')])

        group.refresh_from_db()
        self.assertEqual(group.name, 'new-name')
        self.assertEqual(GroupUUIDMapping.objects.get(entry_uuid='uuid-1').group.pk, group.pk)
        self.assertEqual(Group.objects.count(), 1)

    def test_links_existing_unmapped_group_by_name(self):
        legacy = Group.objects.create(name='legacy')

        self._fire([info('legacy', 'uuid-legacy')])

        self.assertEqual(GroupUUIDMapping.objects.get(entry_uuid='uuid-legacy').group.pk, legacy.pk)
        self.assertEqual(Group.objects.filter(name='legacy').count(), 1)

    def test_skips_entry_without_uuid(self):
        self._fire([('cn=x,ou=Groups,dc=test', {'cn': ['x']})])

        self.assertFalse(GroupUUIDMapping.objects.exists())
        self.assertFalse(Group.objects.exists())

    def test_idempotent_on_repeat(self):
        infos = [info('foo', 'uuid-foo'), info('bar', 'uuid-bar')]

        self._fire(infos)
        self._fire(infos)

        self.assertEqual(Group.objects.count(), 2)
        self.assertEqual(GroupUUIDMapping.objects.count(), 2)
