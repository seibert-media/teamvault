import re
import uuid
from types import SimpleNamespace
from unittest.mock import Mock

import ldap
from django.contrib.auth.models import Group, Permission
from django.db import connection
from django.test import TestCase, TransactionTestCase, override_settings
from django_auth_ldap.backend import populate_user
from django_auth_ldap.config import GroupOfNamesType, LDAPSearch

from teamvault.apps.accounts.models import GroupUUIDMapping, UserProfile
from teamvault.apps.accounts.signals import sync_group_uuids_before_mirror
from teamvault.apps.audit.auditlog import log
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry
from teamvault.apps.secrets.models import SharedSecretData
from teamvault.apps.secrets.tests.utils import make_user, new_secret


class FakeLDAPConnection:
    """Answers by-UUID group searches from a {entry_uuid: name} directory."""

    def __init__(self, directory):
        self.directory = directory
        self.filterstrs = []

    def search_s(self, base, scope, filterstr, attrlist=None):  # noqa: ARG002
        self.filterstrs.append(filterstr)
        entry_uuid = re.search(r'\(entryUUID=([^)\\]+)\)', filterstr).group(1)
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


GUID = uuid.UUID('12345678-1234-5678-9abc-123456789abc')


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

    def test_rename_creates_audit_log_entry(self):
        group = Group.objects.create(name='old-name')
        GroupUUIDMapping.objects.create(group=group, entry_uuid='uuid-1')

        self._fire([info('new-name', 'uuid-1')])

        self.assertTrue(LogEntry.objects.filter(group=group).exists())

    def test_rename_succeeds_despite_group_named_like_temp_placeholder(self):
        group = Group.objects.create(name='old-name')
        GroupUUIDMapping.objects.create(group=group, entry_uuid='uuid-1')
        decoy = Group.objects.create(name=f'_teamvault_rename_{group.pk}')

        self._fire([info('new-name', 'uuid-1')])

        group.refresh_from_db()
        decoy.refresh_from_db()
        self.assertEqual(group.name, 'new-name')
        self.assertEqual(decoy.name, f'_teamvault_rename_{group.pk}')

    def test_links_existing_unmapped_group_by_name(self):
        legacy = Group.objects.create(name='legacy')

        self._fire([info('legacy', 'uuid-legacy')])

        self.assertEqual(GroupUUIDMapping.objects.get(entry_uuid='uuid-legacy').group.pk, legacy.pk)
        self.assertEqual(Group.objects.filter(name='legacy').count(), 1)

    def test_canonicalizes_binary_guid_value(self):
        self._fire([('cn=ad-team,ou=Groups,dc=test', {'cn': ['ad-team'], 'entryUUID': [GUID.bytes_le]})])

        mapping = GroupUUIDMapping.objects.get(entry_uuid=str(GUID))
        self.assertEqual(mapping.group.name, 'ad-team')

    def test_skips_group_with_unusable_uuid_value(self):
        with self.assertLogs('teamvault.apps.accounts.signals', level='ERROR'):
            self._fire([
                ('cn=broken,ou=Groups,dc=test', {'cn': ['broken'], 'entryUUID': [b'\xff\xfe\xfd']}),
                info('intact', 'uuid-intact'),
            ])

        self.assertFalse(Group.objects.filter(name='broken').exists())
        self.assertTrue(GroupUUIDMapping.objects.filter(entry_uuid='uuid-intact').exists())

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
        collider.refresh_from_db()
        self.assertEqual(mapped.name, 'new-name')
        self.assertEqual(collider.name, f'new-name_merged_{collider.pk}_stale')
        self.assertIn(member, mapped.user_set.all())
        self.assertTrue(SharedSecretData.objects.filter(secret=secret, group=mapped).exists())
        self.assertIn(mapped, profile.default_sharing_groups.all())
        self.assertTrue(LogEntry.objects.filter(group=mapped).exists())
        # the husk must not retain anything that still grants access
        self.assertFalse(collider.user_set.exists())
        self.assertFalse(SharedSecretData.objects.filter(group=collider).exists())
        self.assertNotIn(collider, profile.default_sharing_groups.all())

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

    def test_merge_survives_collider_audit_history(self):
        mapped = self._mapped_group('old-name', 'uuid-1')
        collider = Group.objects.create(name='new-name')
        log('share granted', category=AuditLogCategoryChoices.MISCELLANEOUS, group=collider)

        fire([info('new-name', 'uuid-1')])

        mapped.refresh_from_db()
        collider.refresh_from_db()
        self.assertEqual(mapped.name, 'new-name')
        self.assertEqual(collider.name, f'new-name_merged_{collider.pk}_stale')
        self.assertTrue(LogEntry.objects.filter(group=collider).exists())

    def test_merge_transfers_permissions(self):
        mapped = self._mapped_group('old-name', 'uuid-1')
        collider = Group.objects.create(name='new-name')
        permission = Permission.objects.first()
        collider.permissions.add(permission)

        fire([info('new-name', 'uuid-1')])

        self.assertIn(permission, mapped.permissions.all())
        self.assertFalse(collider.permissions.exists())

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

    def test_liveness_lookup_also_matches_binary_guid_form(self):
        mapped = self._mapped_group('old-name', 'uuid-1')
        other = self._mapped_group('new-name', str(GUID))
        connection_directory = {str(GUID): 'renamed-elsewhere'}
        ldap_user = fake_ldap_user([info('new-name', 'uuid-1')], connection_directory)

        sync_group_uuids_before_mirror(sender=Mock(), user=Mock(), ldap_user=ldap_user)

        mapped.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual(mapped.name, 'new-name')
        self.assertEqual(other.name, 'renamed-elsewhere')
        escaped_binary = ''.join(f'\\{byte:02x}' for byte in GUID.bytes_le)
        self.assertTrue(any(escaped_binary in filterstr for filterstr in ldap_user.connection.filterstrs))

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


@override_settings(
    AUTH_LDAP_GROUP_ENTRY_UUID_ATTR='entryUUID',
    AUTH_LDAP_GROUP_SEARCH=LDAPSearch('ou=groups,dc=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
    AUTH_LDAP_GROUP_TYPE=GroupOfNamesType(),
)
class NewUUIDConflictTests(TestCase):
    """A new LDAP UUID whose name hits a Django group already mapped to a different UUID."""

    @staticmethod
    def _mapped_group(name, entry_uuid):
        group = Group.objects.create(name=name)
        GroupUUIDMapping.objects.create(group=group, entry_uuid=entry_uuid)
        return group

    def test_rebinds_mapping_when_ldap_group_was_recreated(self):
        group = self._mapped_group('team', 'uuid-old')

        fire([info('team', 'uuid-new')], directory={})

        mapping = GroupUUIDMapping.objects.get(group=group)
        self.assertEqual(mapping.entry_uuid, 'uuid-new')
        self.assertFalse(GroupUUIDMapping.objects.filter(entry_uuid='uuid-old').exists())
        self.assertEqual(Group.objects.count(), 1)
        self.assertTrue(LogEntry.objects.filter(group=group).exists())

    def test_creates_fresh_group_when_old_uuid_lives_under_new_name(self):
        group = self._mapped_group('team', 'uuid-old')

        fire([info('team', 'uuid-new')], directory={'uuid-old': 'team-renamed'})

        group.refresh_from_db()
        self.assertEqual(group.name, 'team-renamed')
        self.assertEqual(GroupUUIDMapping.objects.get(group=group).entry_uuid, 'uuid-old')
        fresh = Group.objects.get(name='team')
        self.assertEqual(GroupUUIDMapping.objects.get(group=fresh).entry_uuid, 'uuid-new')

    def test_skips_new_uuid_when_live_group_still_owns_name(self):
        group = self._mapped_group('team', 'uuid-old')

        with self.assertLogs('teamvault.apps.accounts.signals', level='WARNING'):
            fire([info('team', 'uuid-new')], directory={'uuid-old': 'team'})

        self.assertEqual(GroupUUIDMapping.objects.get(group=group).entry_uuid, 'uuid-old')
        self.assertFalse(GroupUUIDMapping.objects.filter(entry_uuid='uuid-new').exists())
        self.assertEqual(Group.objects.count(), 1)

    def test_first_uuid_wins_for_duplicate_names_in_one_sync(self):
        with self.assertLogs('teamvault.apps.accounts.signals', level='WARNING'):
            fire([info('dup', 'uuid-1'), info('dup', 'uuid-2')])

        self.assertEqual(Group.objects.count(), 1)
        mapping = GroupUUIDMapping.objects.get()
        self.assertEqual(mapping.entry_uuid, 'uuid-1')

    def test_ldap_error_during_liveness_check_skips_uuid(self):
        group = self._mapped_group('team', 'uuid-old')
        ldap_user = fake_ldap_user([info('team', 'uuid-new')])
        ldap_user.connection.search_s = Mock(side_effect=ldap.LDAPError)

        with self.assertLogs('teamvault.apps.accounts.signals', level='WARNING'):
            sync_group_uuids_before_mirror(sender=Mock(), user=Mock(), ldap_user=ldap_user)

        self.assertEqual(GroupUUIDMapping.objects.get(group=group).entry_uuid, 'uuid-old')
        self.assertFalse(GroupUUIDMapping.objects.filter(entry_uuid='uuid-new').exists())


@override_settings(
    AUTH_LDAP_GROUP_ENTRY_UUID_ATTR='entryUUID',
    AUTH_LDAP_GROUP_SEARCH=LDAPSearch('ou=groups,dc=test', ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
    AUTH_LDAP_GROUP_TYPE=GroupOfNamesType(),
)
class TransactionBoundaryTests(TransactionTestCase):
    def test_no_ldap_io_while_transaction_is_open(self):
        # LDAP is remote network I/O; doing it inside the atomic block would hold row
        # locks on auth_group for the duration of the calls on every login.
        mapped = Group.objects.create(name='old-name')
        GroupUUIDMapping.objects.create(group=mapped, entry_uuid='uuid-1')
        other = Group.objects.create(name='new-name')
        GroupUUIDMapping.objects.create(group=other, entry_uuid='uuid-2')
        ldap_user = fake_ldap_user([info('new-name', 'uuid-1')], {'uuid-2': 'renamed-elsewhere'})

        searched_in_atomic_block = []
        original_search_s = ldap_user.connection.search_s

        def recording_search_s(*args, **search_kwargs):
            searched_in_atomic_block.append(connection.in_atomic_block)
            return original_search_s(*args, **search_kwargs)

        ldap_user.connection.search_s = recording_search_s

        sync_group_uuids_before_mirror(sender=Mock(), user=Mock(), ldap_user=ldap_user)

        mapped.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual(mapped.name, 'new-name')
        self.assertEqual(other.name, 'renamed-elsewhere')
        self.assertTrue(searched_in_atomic_block)
        self.assertNotIn(True, searched_in_atomic_block)


@override_settings(AUTH_LDAP_GROUP_ENTRY_UUID_ATTR='entryUUID')
class SignalConnectionTests(TestCase):
    def test_receiver_connected_to_populate_user(self):
        populate_user.send(sender=Mock, user=Mock(), ldap_user=fake_ldap_user([info('engineering', 'uuid-eng')]))

        self.assertTrue(Group.objects.filter(name='engineering').exists())
        self.assertTrue(GroupUUIDMapping.objects.filter(entry_uuid='uuid-eng').exists())
