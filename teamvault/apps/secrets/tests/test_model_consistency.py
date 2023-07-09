from django.contrib.auth.models import User, Group
from django.db import IntegrityError
from django.test import TestCase

from teamvault.apps.secrets.models import Secret, SharedSecretData


class SecretConsistencyTestCase(TestCase):
    def setUp(self):
        User.objects.create(username='testuser')
        Group.objects.create(name='testgroup')

    def test_secret_unique_together(self):
        user = User.objects.get(username='testuser')
        group = Group.objects.get(name='testgroup')

        secret = Secret.objects.create(name="testsecret", created_by=user)
        secret.shared_users.add(user, through_defaults={})
        secret.shared_groups.add(group, through_defaults={})

        with self.assertRaises(IntegrityError):
            SharedSecretData.objects.create(secret=secret, user=user)
            SharedSecretData.objects.create(secret=secret, group=group)

    def test_shared_secret_data_only_one_constraint(self):
        user = User.objects.get(username='testuser')
        group = Group.objects.get(name='testgroup')
        secret = Secret.objects.create(name="testsecret", created_by=user)

        with self.assertRaises(IntegrityError):
            SharedSecretData.objects.create(secret=secret, group=group, user=user)
