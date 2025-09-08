from datetime import timedelta

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.utils.timezone import now

from teamvault.apps.secrets.models import Secret, AccessPermissionTypes, SharedSecretData
from teamvault.apps.secrets.tests.helpers import make_secret, STATIC_TEST_KEY
from teamvault.apps.secrets.exceptions import PermissionError

User = get_user_model()


@override_settings(TEAMVAULT_SECRET_KEY=STATIC_TEST_KEY)
class SecretReadPermissionTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user('owner')
        self.other = User.objects.create_user('other')

    def test_any_policy_allows_anyone(self):
        secret = make_secret(self.owner, share_with_owner=False, access_policy=Secret.ACCESS_POLICY_ANY)
        self.assertEqual(secret.is_readable_by_user(self.owner), AccessPermissionTypes.ALLOWED)

    def test_permanent_share_grants_read_permission(self):
        secret = make_secret(self.owner)
        SharedSecretData.objects.create(secret=secret, user=self.other, granted_by=self.owner)
        self.assertEqual(secret.is_readable_by_user(self.other), AccessPermissionTypes.ALLOWED)

    def test_temp_share_returns_temp_allowed(self):
        secret = make_secret(self.owner)
        SharedSecretData.objects.create(secret=secret, user=self.other, granted_by=self.owner,
                                        granted_until=now() + timedelta(days=1))
        self.assertEqual(secret.is_readable_by_user(self.other), AccessPermissionTypes.TEMPORARILY_ALLOWED)

    def test_expired_share_returns_not_allowed(self):
        secret = make_secret(self.owner)
        SharedSecretData.objects.create(secret=secret, user=self.other, granted_by=self.owner,
                                        granted_until=now() - timedelta(days=1))
        self.assertEqual(secret.is_readable_by_user(self.other), AccessPermissionTypes.NOT_ALLOWED)

    def test_read_requires_permission(self):
        secret = make_secret(self.owner)
        with self.assertRaises(PermissionError):
            secret.get_data(self.other)
