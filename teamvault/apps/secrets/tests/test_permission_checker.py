from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils.timezone import now

from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
from teamvault.apps.secrets.models import (
    AccessPermissionTypes,
    PermissionChecker,
    SharedSecretData,
)

from .utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class PermissionCheckerTests(TestCase):
    def setUp(self):
        self.alice = make_user('alice', superuser=True)
        self.bob = make_user('bob')
        self.owner = make_user('owner')

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
