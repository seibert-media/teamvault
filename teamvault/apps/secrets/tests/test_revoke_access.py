from datetime import timedelta
from unittest.mock import patch
from django.test import TransactionTestCase
from django.utils.datetime_safe import datetime
from django.utils.timezone import make_aware

from teamvault.apps.secrets.models import Secret
from teamvault.apps.audit.models import LogEntry
from django.contrib.auth.models import User, Group
from teamvault.apps.secrets.revoke_access import revoke_unused_access

from django.conf import settings


class RevokeAccessTests(TransactionTestCase):
    def setUp(self):
        # Set up data for the tests
        self.user1 = User.objects.create(username='user1', password='pass')
        self.user1.email = 'foo@bar.com'
        self.user2 = User.objects.create(username='user2', password='pass')
        self.user2.email = 'foo@bar.com'
        self.user2.last_name = 'Foo'
        self.user2.save()
        self.secret1 = Secret.objects.create(name='secret1', created_by=self.user1)
        self.secret1.share_data.create(user=self.user1, secret=self.secret1)
        self.secret1.share_data.create(user=self.user2, secret=self.secret1)

        # Create groups
        self.group1 = Group.objects.create(name='group1')
        self.group2 = Group.objects.create(name='group2')
        # Add users to groups
        self.group1.user_set.add(self.user1)
        self.group2.user_set.add(self.user2)
        # Add secret to both groups
        self.group_secret = Secret.objects.create(name='group_secret', created_by=self.user1)
        self.group_secret.share_data.create(group=self.group1, secret=self.group_secret)
        self.group_secret.share_data.create(group=self.group2, secret=self.group_secret)

        # user1 from group1 accessed group_secret recently
        with patch('django.utils.timezone.now', return_value=make_aware(datetime.now())):
            LogEntry.objects.create(
                message="access",
                actor=self.user1,
                secret=self.group_secret,
            )

        # user2 from group2 accessed group_secret long time ago
        with patch('django.utils.timezone.now', return_value=make_aware(
                datetime.now() - timedelta(days=settings.DAYS_UNTIL_ACCESS_REVOKE + 1))):
            LogEntry.objects.create(
                message="access",
                actor=self.user2,
                secret=self.group_secret,
            )

        # User1 accessed the secret1 recently
        with patch('django.utils.timezone.now', return_value=make_aware(datetime.now())):
            LogEntry.objects.create(
                message="access",
                actor=self.user1,
                secret=self.secret1,
            )

        # User2 accessed the secret1 long ago
        with patch('django.utils.timezone.now', return_value=make_aware(
                datetime.now() - timedelta(days=settings.DAYS_UNTIL_ACCESS_REVOKE + 1))):
            LogEntry.objects.create(
                message="access",
                actor=self.user2,
                secret=self.secret1,
            )

    def test_revoke_access(self):
        print(self.user1.pk)
        # Before calling the function, both users and groups should have access to the secret
        self.assertIn(self.user1.pk, self.secret1.share_data.users().values_list('user__pk', flat=True))
        self.assertIn(self.user2.pk, self.secret1.share_data.users().values_list('user__pk', flat=True))
        self.assertIn(self.group1.pk, self.group_secret.share_data.groups().values_list('group__pk', flat=True))
        self.assertIn(self.group2.pk, self.group_secret.share_data.groups().values_list('group__pk', flat=True))

        revoke_unused_access()

        # After calling the function, only user1 and group1 should have access, as user2's access was revoked
        self.assertIn(self.user1.pk, self.secret1.share_data.users().values_list('user__pk', flat=True))
        self.assertNotIn(self.user2.pk, self.secret1.share_data.users().values_list('user__pk', flat=True))
        self.assertIn(self.group1.pk, self.group_secret.share_data.groups().values_list('group__pk', flat=True))
        self.assertNotIn(self.group2.pk, self.group_secret.share_data.groups().values_list('group__pk', flat=True))

