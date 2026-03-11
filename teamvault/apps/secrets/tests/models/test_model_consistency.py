from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import IntegrityError
from django.test import TestCase

from teamvault.apps.secrets.models import Secret, SharedSecretData

User = get_user_model()


class SecretConsistencyTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create(username='testuser')
        self.group = Group.objects.create(name='testgroup')

    def test_secret_unique_together(self):
        secret = Secret.objects.create(name='testsecret', created_by=self.user)
        secret.shared_users.add(self.user, through_defaults={})
        secret.shared_groups.add(self.group, through_defaults={})

        with self.assertRaises(IntegrityError):
            SharedSecretData.objects.create(secret=secret, user=self.user)
            SharedSecretData.objects.create(secret=secret, group=self.group)

    def test_shared_secret_data_only_one_constraint(self):
        secret = Secret.objects.create(name='testsecret', created_by=self.user)

        with self.assertRaises(IntegrityError):
            SharedSecretData.objects.create(secret=secret, group=self.group, user=self.user)
