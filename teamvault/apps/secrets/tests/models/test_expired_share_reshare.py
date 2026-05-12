from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils.timezone import now

from teamvault.apps.secrets.models import SharedSecretData
from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class ReshareAfterExpiryTests(TestCase):
    """Verify that expired shares don't block new shares."""

    def setUp(self):
        self.owner = make_user('owner')
        self.target = make_user('target')
        self.secret = new_secret(self.owner)

    def test_can_reshare_after_share_expires(self):
        """An expired share for user/secret should not block creating a new one."""
        # Create a share that's already expired
        SharedSecretData.objects.create(
            secret=self.secret,
            user=self.target,
            granted_by=self.owner,
            granted_until=now() - timedelta(days=1),
        )

        # Re-sharing should succeed — Secret.share() deletes the expired row first
        new_share = self.secret.share(
            grant_description='re-shared after expiry',
            granted_by=self.owner,
            user=self.target,
            granted_until=now() + timedelta(weeks=1),
        )
        self.assertIsNotNone(new_share)
        self.assertEqual(new_share.user, self.target)

        # Only one share should exist for this user/secret pair
        self.assertEqual(
            SharedSecretData.objects.filter(secret=self.secret, user=self.target).count(),
            1,
        )
