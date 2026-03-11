from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import IntegrityError
from django.test import TestCase

from teamvault.apps.secrets.models import SharedSecretData
from ..utils import make_user, new_secret

User = get_user_model()


class ShareConstraintsTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.u = make_user('other')
        self.g = Group.objects.create(name='g')
        self.s = new_secret(self.owner, share_with_owner=False)

    def test_only_one_of_user_or_group(self):
        with self.assertRaises(IntegrityError):
            SharedSecretData.objects.create(secret=self.s, user=self.u, group=self.g, granted_by=self.owner)

    def test_unique_user_secret_pair(self):
        SharedSecretData.objects.create(secret=self.s, user=self.u, granted_by=self.owner)
        with self.assertRaises(IntegrityError):
            SharedSecretData.objects.create(secret=self.s, user=self.u, granted_by=self.owner)

    def test_unique_group_secret_pair(self):
        SharedSecretData.objects.create(secret=self.s, group=self.g, granted_by=self.owner)
        with self.assertRaises(IntegrityError):
            SharedSecretData.objects.create(secret=self.s, group=self.g, granted_by=self.owner)
