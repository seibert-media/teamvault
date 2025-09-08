from datetime import timezone, timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test.testcases import TestCase
from django.utils.timezone import now

from teamvault.apps.secrets.models import Secret, AccessPermissionTypes, SharedSecretData
from teamvault.apps.secrets.tests.helpers import STATIC_TEST_KEY, make_secret
from django.test import override_settings

User = get_user_model()


@override_settings(TEAMVAULT_SECRET_KEY=STATIC_TEST_KEY)
class SecretVisibilityPermissionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username='owner', password='x')
        cls.alice = User.objects.create_user(username='alice', password='x')
        cls.bob = User.objects.create_user(username='bob', password='x')
        cls.superuser = User.objects.create_user(username='superuser', password='x', is_superuser=True, is_staff=True)
        cls.group = Group.objects.create(name='devs')

    def test_discoverable_visible_withoth_share(self):
        s = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_DISCOVERABLE)
        self.assertEqual(s.is_visible_to_user(self.alice), AccessPermissionTypes.ALLOWED)

    def test_everyone_policy_visible_to_everyone(self):
        s = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_ANY)
        self.assertEqual(s.is_visible_to_user(self.bob), AccessPermissionTypes.ALLOWED)
        self.assertEqual(s.is_visible_to_user(self.alice), AccessPermissionTypes.ALLOWED)

    def test_hidden_not_visible_without_share(self):
        s = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_HIDDEN)
        self.assertEqual(s.is_visible_to_user(self.alice), AccessPermissionTypes.NOT_ALLOWED)
        self.assertEqual(s.is_visible_to_user(self.bob), AccessPermissionTypes.NOT_ALLOWED)
        self.assertEqual(s.is_visible_to_user(self.owner), AccessPermissionTypes.NOT_ALLOWED)

    def test_hidden_visible_with_user_share(self):
        s = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_HIDDEN)
        SharedSecretData.objects.create(secret=s, user=self.alice, granted_by=self.owner)
        self.assertEqual(s.is_visible_to_user(self.alice), AccessPermissionTypes.ALLOWED)
        self.assertEqual(s.is_visible_to_user(self.bob), AccessPermissionTypes.NOT_ALLOWED)

    def test_hidden_visible_with_group_share(self):
        s = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_HIDDEN)
        self.alice.groups.add(self.group)
        SharedSecretData.objects.create(secret=s, group=self.group, granted_by=self.owner)
        self.assertEqual(s.is_visible_to_user(self.alice), AccessPermissionTypes.ALLOWED)
        self.assertEqual(s.is_visible_to_user(self.bob), AccessPermissionTypes.NOT_ALLOWED)

    def test_hidden_not_visible_with_expired_sahre(self):
        s = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_HIDDEN)
        SharedSecretData.objects.create(secret=s, user=self.alice, granted_by=self.owner,
                                        granted_until=now() - timedelta(days=1))
        self.assertEqual(s.is_visible_to_user(self.alice), AccessPermissionTypes.NOT_ALLOWED)

    def test_superuser_is_always_visible(self):
        s = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_HIDDEN)
        self.assertEqual(s.is_visible_to_user(self.superuser), AccessPermissionTypes.SUPERUSER_ALLOWED)
        self.assertEqual(s.is_visible_to_user(self.owner), AccessPermissionTypes.NOT_ALLOWED)

    def test_deleted_secret_not_visible_even_if_shared(self):
        s = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_DISCOVERABLE)
        SharedSecretData.objects.create(secret=s, user=self.alice, granted_by=self.owner)
        s.status = Secret.STATUS_DELETED
        self.assertEqual(s.is_visible_to_user(self.alice), AccessPermissionTypes.NOT_ALLOWED)
