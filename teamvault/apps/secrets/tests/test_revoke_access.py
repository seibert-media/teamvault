from datetime import timedelta
from unittest.mock import patch
from django.test import TransactionTestCase
from django.utils.datetime_safe import datetime
from django.utils.timezone import make_aware

from teamvault.apps.secrets.models import Secret
from teamvault.apps.audit.models import LogEntry
from django.contrib.auth.models import User
from teamvault.apps.secrets.revoke_access import revoke_access, get_last_access_time

from teamvault.settings import CONFIG


class RevokeAccessTests(TransactionTestCase):
    def setUp(self):
        # Set up data for the tests
        self.user1 = User.objects.create_user(username='user1', password='pass')
        self.user2 = User.objects.create(username='user2', password='pass')
        self.secret1 = Secret.objects.create(name='secret1', created_by=self.user1)
        self.secret1.allowed_users.add(self.user1, self.user2)

        # User1 accessed the secret1 recently
        with patch('django.utils.timezone.now', return_value=make_aware(datetime.now())):
            LogEntry.objects.create(
                message="access",
                actor=self.user1,
                secret=self.secret1,
            )

        # User2 accessed the secret1 long ago
        with patch('django.utils.timezone.now', return_value=make_aware(
                datetime.now() - timedelta(days=int(CONFIG['teamvault']["days_until_revoke"]) + 1))):
            LogEntry.objects.create(
                message="access",
                actor=self.user2,
                secret=self.secret1,
            )

    def test_revoke_access(self):
        # Before calling the function, both users should have access to the secret
        self.assertIn(self.user1, self.secret1.allowed_users.all())
        self.assertIn(self.user2, self.secret1.allowed_users.all())

        revoke_access()

        # After calling the function, only user1 should have access, as user2's access was revoked
        self.assertIn(self.user1, self.secret1.allowed_users.all())
        self.assertNotIn(self.user2, self.secret1.allowed_users.all())
