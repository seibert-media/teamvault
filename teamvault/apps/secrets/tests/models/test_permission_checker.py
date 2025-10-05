from datetime import timedelta

from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.utils.timezone import now

from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
from teamvault.apps.secrets.models import (
    AccessPermissionTypes,
    PermissionChecker,
    SharedSecretData, Secret,
)

from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class PermissionCheckerTests(TestCase):
    def setUp(self):
        self.alice = make_user('alice', superuser=True)
        self.bob = make_user('bob')
        self.dave = make_user('dave')
        self.owner = make_user('owner')
        self.group = Group.objects.create(name='foo')

    def _assert_perm(
            self,
            checker: PermissionChecker,
            *,
            readable,
            shareable,
            visible,
            msg=None,
    ):
        self.assertEqual(checker.is_readable(), readable, msg)
        self.assertEqual(checker.is_shareable(), shareable, msg)
        self.assertEqual(checker.is_visible(), visible, msg)

    def test_policy_any_for_everyone(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.ANY)
        chk = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk,
            readable=AccessPermissionTypes.ALLOWED,
            shareable=AccessPermissionTypes.ALLOWED,
            visible=AccessPermissionTypes.ALLOWED,
        )

    def test_discoverable_without_share(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.DISCOVERABLE)
        chk = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk,
            readable=AccessPermissionTypes.NOT_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.ALLOWED,
        )

    def test_hidden_with_temp_and_perm_shares(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)

        # temporary share (expires tomorrow)  → readable TEMP, shareable NOT
        SharedSecretData.objects.create(
            secret=sec,
            user=self.bob,
            granted_by=self.owner,
            grant_description='tmp',
            granted_until=now() + timedelta(days=1),
        )
        chk_tmp = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk_tmp,
            readable=AccessPermissionTypes.TEMPORARILY_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.ALLOWED,
            msg='temporary share',
        )

        # replace by permanent share → readable ALLOWED, shareable ALLOWED
        SharedSecretData.objects.all().delete()
        SharedSecretData.objects.create(
            secret=sec,
            user=self.bob,
            granted_by=self.owner,
            grant_description='permanent',
            granted_until=None,
        )
        chk_perm = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk_perm,
            readable=AccessPermissionTypes.ALLOWED,
            shareable=AccessPermissionTypes.ALLOWED,
            visible=AccessPermissionTypes.ALLOWED,
            msg='permanent share',
        )

    def test_deleted_secret_is_never_visible(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.ANY)
        sec.status = SecretStatus.DELETED
        sec.save()

        chk = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk,
            readable=AccessPermissionTypes.NOT_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.NOT_ALLOWED,
        )

    def test_superuser_override(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        chk = PermissionChecker(self.alice, sec, sec.share_data.for_user(self.alice))
        self._assert_perm(
            chk,
            readable=AccessPermissionTypes.SUPERUSER_ALLOWED,
            shareable=AccessPermissionTypes.SUPERUSER_ALLOWED,
            visible=AccessPermissionTypes.ALLOWED,  # still listed
        )

    def test_expired_share_returns_not_allowed(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        SharedSecretData.objects.create(
            secret=sec,
            user=self.bob,
            granted_by=self.owner,
            grant_description='temporary',
            granted_until=now() - timedelta(days=1)
        )
        chk = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk,
            readable=AccessPermissionTypes.NOT_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.NOT_ALLOWED
        )

    def test_temp_share_expires_exactly_at_now_is_not_allowed(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        SharedSecretData.objects.create(
            secret=sec,
            user=self.bob,
            granted_by=self.owner,
            grant_description='temporary',
            granted_until=now()
        )
        chk = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk,
            readable=AccessPermissionTypes.NOT_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.NOT_ALLOWED,
        )

    def test_group_share_permanent_grants_access(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        self.group.user_set.add(self.dave)
        SharedSecretData.objects.create(
            secret=sec,
            group=self.group,
            granted_by=self.owner,
            grant_description='permanent group share',
        )
        chk_dave = PermissionChecker(self.dave, sec, sec.share_data.for_user(self.dave))
        chk_bob = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk_dave,
            readable=AccessPermissionTypes.ALLOWED,
            shareable=AccessPermissionTypes.ALLOWED,
            visible=AccessPermissionTypes.ALLOWED,
        )
        self._assert_perm(
            chk_bob,
            readable=AccessPermissionTypes.NOT_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.NOT_ALLOWED,
        )

    def test_group_share_expired_denies_access(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        self.group.user_set.add(self.dave)
        SharedSecretData.objects.create(
            secret=sec,
            group=self.group,
            granted_by=self.owner,
            grant_description='expired group share',
            granted_until=now() - timedelta(days=1)
        )
        chk_dave = PermissionChecker(self.dave, sec, sec.share_data.for_user(self.dave))
        self._assert_perm(
            chk_dave,
            readable=AccessPermissionTypes.NOT_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.NOT_ALLOWED,
        )

    @override_settings(ALLOW_SUPERUSER_READS=False)
    def test_superuser_override_disabled_denies_any_access(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        chk = PermissionChecker(self.alice, sec, sec.share_data.for_user(self.alice))
        self._assert_perm(
            chk,
            readable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.NOT_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
        )

    def test_deleted_secret_denies_even_if_shared(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        SharedSecretData.objects.create(secret=sec, user=self.bob, granted_by=self.owner)
        sec.status = SecretStatus.DELETED
        sec.save()

        chk = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self._assert_perm(
            chk,
            readable=AccessPermissionTypes.NOT_ALLOWED,
            shareable=AccessPermissionTypes.NOT_ALLOWED,
            visible=AccessPermissionTypes.NOT_ALLOWED,
        )

    def test_collection_helpers_match_permission_checker(self):
        sec = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        SharedSecretData.objects.create(secret=sec, user=self.bob, granted_by=self.owner)

        # collection helpers
        vis_qs = Secret.get_all_visible_to_user(self.bob)
        self.assertIn(sec, vis_qs)

        read_qs = Secret.get_all_readable_by_user(self.bob)
        self.assertIn(sec, read_qs)

        # per-item PermissionChecker
        chk = PermissionChecker(self.bob, sec, sec.share_data.for_user(self.bob))
        self.assertEqual(chk.is_visible(), AccessPermissionTypes.ALLOWED)
        self.assertEqual(chk.is_readable(), AccessPermissionTypes.ALLOWED)
