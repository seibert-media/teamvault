import re
from unittest.mock import Mock, patch

import ldap
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import SimpleTestCase, TestCase, override_settings
from django_auth_ldap.config import LDAPSearch, MemberDNGroupType

from teamvault.apps.accounts.models import GroupUUIDMapping
from teamvault.apps.accounts.tasks import LDAPGroupSyncAborted, sync_ldap_group_members, sync_ldap_groups
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry

User = get_user_model()

USER_BASE = 'ou=users,dc=test'
GROUP_BASE = 'ou=groups,dc=test'


def user_dn(username):
    return f'uid={username},{USER_BASE}'


class FakeDirectory:
    """Answers the searches the sync issues: user by uid, all groups, and groups by member DN."""

    def __init__(self, *, users, groups):
        self.users = users
        # {name: (uuid, member usernames)}
        self.groups = groups

    def group_info(self, name):
        ldap_uuid, _members = self.groups[name]
        return f'cn={name},{GROUP_BASE}', {'cn': [name], 'entryUUID': [ldap_uuid]}

    def search_s(self, base, _scope, filterstr, _attrlist=None):
        if base == USER_BASE:
            username = filterstr.removeprefix('(uid=').removesuffix(')')
            return [(user_dn(username), {'uid': [username]})] if username in self.users else []
        member = re.search(r'\(member=(.+)\)\)$', filterstr)
        return [
            self.group_info(name)
            for name, (_uuid, members) in self.groups.items()
            if member is None or member.group(1) in {user_dn(username) for username in members}
        ]

    def unbind_s(self):
        pass


class FailingOnBob(FakeDirectory):
    def search_s(self, base, scope, filterstr, attrlist=None):
        if filterstr == '(uid=bob)':
            raise ldap.SERVER_DOWN
        return super().search_s(base, scope, filterstr, attrlist)


@override_settings(
    LDAP_AUTH_ENABLED=True,
    AUTH_LDAP_SERVER_URI='ldap://ldap.test',
    AUTH_LDAP_GROUP_UUID_ATTR=None,
    AUTH_LDAP_USER_SEARCH=LDAPSearch(USER_BASE, ldap.SCOPE_SUBTREE, '(uid=%(user)s)'),
    AUTH_LDAP_GROUP_SEARCH=LDAPSearch(GROUP_BASE, ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)'),
    AUTH_LDAP_GROUP_TYPE=MemberDNGroupType('member'),
)
class SyncLDAPGroupsTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create(username='alice')
        self.bob = User.objects.create(username='bob')
        self.engineering = Group.objects.create(name='engineering')

    @staticmethod
    def _sync(directory):
        connection = Mock(wraps=directory)
        with patch('teamvault.apps.accounts.tasks._get_ldap_connection', return_value=connection):
            sync_ldap_groups()

    def test_removes_users_no_longer_in_ldap_group(self):
        self.engineering.user_set.add(self.alice, self.bob)

        self._sync(FakeDirectory(users={'alice', 'bob'}, groups={'engineering': ('u-eng', {'alice'})}))

        self.assertEqual(set(self.engineering.user_set.all()), {self.alice})

    def test_adds_existing_users_who_joined_ldap_group(self):
        self._sync(FakeDirectory(users={'alice', 'bob'}, groups={'engineering': ('u-eng', {'alice', 'carol'})}))

        self.assertEqual(set(self.engineering.user_set.all()), {self.alice})
        self.assertFalse(User.objects.filter(username='carol').exists())

    def test_removes_users_missing_from_ldap(self):
        self.engineering.user_set.add(self.alice, self.bob)

        self._sync(FakeDirectory(users={'alice'}, groups={'engineering': ('u-eng', {'alice', 'bob'})}))

        self.assertEqual(set(self.engineering.user_set.all()), {self.alice})

    def test_empties_group_without_ldap_members(self):
        self.engineering.user_set.add(self.alice, self.bob)

        self._sync(
            FakeDirectory(
                users={'alice', 'bob'},
                groups={'engineering': ('u-eng', set()), 'other': ('u-other', {'alice'})},
            )
        )

        self.assertFalse(self.engineering.user_set.exists())

    def test_leaves_groups_without_ldap_counterpart_alone(self):
        local = Group.objects.create(name='local')
        local.user_set.add(self.bob)

        self._sync(FakeDirectory(users={'alice', 'bob'}, groups={'engineering': ('u-eng', {'alice'})}))

        self.assertEqual(set(local.user_set.all()), {self.bob})

    def test_does_not_add_inactive_users(self):
        self.bob.is_active = False
        self.bob.save()

        self._sync(FakeDirectory(users={'alice', 'bob'}, groups={'engineering': ('u-eng', {'alice', 'bob'})}))

        self.assertEqual(set(self.engineering.user_set.all()), {self.alice})

    @override_settings(AUTH_LDAP_GROUP_UUID_ATTR='entryUUID')
    def test_matches_renamed_group_by_uuid_mapping(self):
        GroupUUIDMapping.objects.create(group=self.engineering, ldap_uuid='u-eng')

        self._sync(FakeDirectory(users={'alice', 'bob'}, groups={'platform': ('u-eng', {'bob'})}))

        self.assertEqual(set(self.engineering.user_set.all()), {self.bob})

    def test_writes_audit_log_entries(self):
        self.engineering.user_set.add(self.bob)

        self._sync(FakeDirectory(users={'alice', 'bob'}, groups={'engineering': ('u-eng', {'alice'})}))

        entries = {(entry.category, entry.user, entry.group) for entry in LogEntry.objects.all()}
        self.assertEqual(
            entries,
            {
                (AuditLogCategoryChoices.GROUP_MEMBER_ADDED, self.alice, self.engineering),
                (AuditLogCategoryChoices.GROUP_MEMBER_REMOVED, self.bob, self.engineering),
            },
        )

    def test_aborts_without_ldap_groups(self):
        self.engineering.user_set.add(self.alice)

        with self.assertRaises(LDAPGroupSyncAborted):
            self._sync(FakeDirectory(users={'alice'}, groups={}))

        self.assertEqual(set(self.engineering.user_set.all()), {self.alice})

    def test_aborts_when_no_user_is_found(self):
        self.engineering.user_set.add(self.alice)

        with self.assertRaises(LDAPGroupSyncAborted):
            self._sync(FakeDirectory(users=set(), groups={'engineering': ('u-eng', {'alice'})}))

        self.assertEqual(set(self.engineering.user_set.all()), {self.alice})

    def test_ldap_error_changes_nothing(self):
        self.engineering.user_set.add(self.alice, self.bob)
        directory = FailingOnBob(users={'alice', 'bob'}, groups={'engineering': ('u-eng', set())})

        with self.assertRaises(ldap.SERVER_DOWN):
            self._sync(directory)

        self.assertEqual(set(self.engineering.user_set.all()), {self.alice, self.bob})


@override_settings(LDAP_AUTH_ENABLED=True)
class SyncLDAPGroupMembersTaskTests(SimpleTestCase):
    @staticmethod
    def _run(*, enabled):
        with (
            override_settings(HUEY_TASKS={**settings.HUEY_TASKS, 'sync_ldap_groups': enabled}),
            patch('teamvault.apps.accounts.tasks.sync_ldap_groups') as sync,
        ):
            sync_ldap_group_members.call_local()
        return sync

    def test_runs_when_enabled(self):
        self._run(enabled=True).assert_called_once()

    def test_skipped_when_disabled(self):
        self._run(enabled=False).assert_not_called()
