import re
from types import SimpleNamespace
from unittest.mock import Mock

import ldap
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django_auth_ldap.backend import populate_user
from django_auth_ldap.config import GroupOfNamesType, LDAPSearch

from teamvault.apps.accounts.models import GroupUUIDMapping, UserProfile
from teamvault.apps.accounts.signals import sync_group_uuids_before_mirror
from teamvault.apps.audit.models import LogEntry
from teamvault.apps.secrets.models import SharedSecretData
from teamvault.apps.secrets.tests.utils import make_user, new_secret


class FakeLDAPConnection:
    """Answers by-UUID group searches from a {entry_uuid: name} directory."""

    def __init__(self, directory):
        self.directory = directory

    def search_s(self, base, scope, filterstr, attrlist=None):  # noqa: ARG002
        entry_uuid = re.search(r'\(entryUUID=([^)]+)\)', filterstr).group(1)
        if entry_uuid in self.directory:
            return [info(self.directory[entry_uuid], entry_uuid)]
        return []


def fake_ldap_user(group_infos, directory=None):
    """Build the minimal duck-typed `ldap_user` shape the signal touches."""
    groups = SimpleNamespace(
        _get_group_infos=lambda: group_infos,
        _group_type=GroupOfNamesType(),
    )
    return SimpleNamespace(
        _get_groups=lambda: groups,
        connection=FakeLDAPConnection(directory or {}),
    )


def info(name, entry_uuid):
    dn = f'cn={name},ou=Groups,dc=test'
    return dn, {'cn': [name], 'entryUUID': [entry_uuid]}


def fire(group_infos, directory=None):
    sync_group_uuids_before_mirror(sender=Mock(), user=Mock(), ldap_user=fake_ldap_user(group_infos, directory))


@override_settings(AUTH_LDAP_GROUP_ENTRY_UUID_ATTR='entryUUID')
class SyncGroupUUIDsBeforeMirrorTests(TestCase):
    @staticmethod
    def _fire(group_infos):
        fire(group_infos)

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

    def test_noop_when_feature_disabled(self):
        with override_settings(AUTH_LDAP_GROUP_ENTRY_UUID_ATTR=None):
            self._fire([info('engineering', 'uuid-eng')])

        self.assertFalse(GroupUUIDMapping.objects.exists())
        self.assertFalse(Group.objects.exists())


@override_settings(
    AUTH_LDAP_GROUP_ENTRY_UUID_ATTR='entryUUID',
    AUTH_LDAP_GROUP_SEARCH=LDAPSearch('ou=groups,dc=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
    AUTH_LDAP_GROUP_TYPE=GroupOfNamesType(),
)
class RenameCollisionTests(TestCase):
    @staticmethod
    def _mapped_group(name, entry_uuid):
        group = Group.objects.create(name=name)
        GroupUUIDMapping.objects.create(group=group, entry_uuid=entry_uuid)
        return group

    def test_merges_unmapped_collider_into_mapped_group(self):
        mapped = self._mapped_group('old-name', 'uuid-1')
        collider = Group.objects.create(name='new-name')
        member = make_user('member')
        collider.user_set.add(member)
        owner = make_user('owner')
        secret = new_secret(owner)
        SharedSecretData.objects.create(secret=secret, group=collider, granted_by=owner)
        profile = UserProfile.objects.create(user=member)
        profile.default_sharing_groups.add(collider)

        fire([info('new-name', 'uuid-1')])

        mapped.refresh_from_db()
        self.assertEqual(mapped.name, 'new-name')
        self.assertFalse(Group.objects.filter(pk=collider.pk).exists())
        self.assertIn(member, mapped.user_set.all())
        self.assertTrue(SharedSecretData.objects.filter(secret=secret, group=mapped).exists())
        self.assertIn(mapped, profile.default_sharing_groups.all())
        self.assertTrue(LogEntry.objects.filter(group=mapped).exists())

    def test_merge_deduplicates_group_shares(self):
        mapped = self._mapped_group('old-name', 'uuid-1')
        collider = Group.objects.create(name='new-name')
        owner = make_user('owner')
        secret = new_secret(owner)
        SharedSecretData.objects.create(secret=secret, group=mapped, granted_by=owner)
        SharedSecretData.objects.create(secret=secret, group=collider, granted_by=owner)

        fire([info('new-name', 'uuid-1')])

        group_shares = SharedSecretData.objects.filter(secret=secret, group__isnull=False)
        self.assertEqual(group_shares.count(), 1)
        self.assertEqual(group_shares.get().group, mapped)

    def test_swaps_names_between_two_mapped_groups(self):
        alpha = self._mapped_group('alpha', 'uuid-a')
        beta = self._mapped_group('beta', 'uuid-b')

        fire([info('beta', 'uuid-a'), info('alpha', 'uuid-b')])

        alpha.refresh_from_db()
        beta.refresh_from_db()
        self.assertEqual(alpha.name, 'beta')
        self.assertEqual(beta.name, 'alpha')
        self.assertEqual(Group.objects.count(), 2)

    def test_chained_rename_frees_name_for_other_mapped_group(self):
        group_a = self._mapped_group('group-a', 'uuid-a')
        group_b = self._mapped_group('group-b', 'uuid-b')

        fire([info('group-c', 'uuid-a'), info('group-a', 'uuid-b')])

        group_a.refresh_from_db()
        group_b.refresh_from_db()
        self.assertEqual(group_a.name, 'group-c')
        self.assertEqual(group_b.name, 'group-a')
        self.assertEqual(Group.objects.count(), 2)

    def test_renames_collider_to_its_current_ldap_name(self):
        mapped = self._mapped_group('old-name', 'uuid-1')
        other = self._mapped_group('new-name', 'uuid-2')

        fire([info('new-name', 'uuid-1')], directory={'uuid-2': 'renamed-elsewhere'})

        mapped.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual(mapped.name, 'new-name')
        self.assertEqual(other.name, 'renamed-elsewhere')

    def test_resolves_chained_collisions_via_ldap_lookups(self):
        first = self._mapped_group('old-name', 'uuid-1')
        second = self._mapped_group('new-name', 'uuid-2')
        third = self._mapped_group('second-new', 'uuid-3')

        fire([info('new-name', 'uuid-1')], directory={'uuid-2': 'second-new', 'uuid-3': 'third-new'})

        first.refresh_from_db()
        second.refresh_from_db()
        third.refresh_from_db()
        self.assertEqual(first.name, 'new-name')
        self.assertEqual(second.name, 'second-new')
        self.assertEqual(third.name, 'third-new')

    def test_renames_stale_collider_aside_when_gone_from_ldap(self):
        mapped = self._mapped_group('old-name', 'uuid-1')
        stale = self._mapped_group('new-name', 'uuid-2')
        member = make_user('member')
        stale.user_set.add(member)

        with self.assertLogs('teamvault.apps.accounts.signals', level='WARNING'):
            fire([info('new-name', 'uuid-1')], directory={})

        mapped.refresh_from_db()
        stale.refresh_from_db()
        self.assertEqual(mapped.name, 'new-name')
        self.assertEqual(stale.name, 'new-name_uuid-2_stale')
        # a mapped collider is a different logical group — it must never be merged
        self.assertIn(member, stale.user_set.all())


@override_settings(AUTH_LDAP_GROUP_ENTRY_UUID_ATTR='entryUUID')
class SignalConnectionTests(TestCase):
    def test_receiver_connected_to_populate_user(self):
        populate_user.send(sender=Mock, user=Mock(), ldap_user=fake_ldap_user([info('engineering', 'uuid-eng')]))

        self.assertTrue(Group.objects.filter(name='engineering').exists())
        self.assertTrue(GroupUUIDMapping.objects.filter(entry_uuid='uuid-eng').exists())
