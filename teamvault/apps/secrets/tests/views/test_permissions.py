from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now

from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import (
    AccessPermissionTypes,
    SharedSecretData,
)
from ..utils import COMMON_OVERRIDES, make_user, new_secret

User = get_user_model()


@override_settings(**COMMON_OVERRIDES)
class SecretCreateFlowTests(TestCase):
    def setUp(self):
        self.user = make_user('dummy')

    def test_creator_can_read_after_create_flow(self):
        secret = new_secret(self.user)
        self.client.force_login(self.user)
        resp = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.ALLOWED)


@override_settings(**COMMON_OVERRIDES)
class SecretReadPermissionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.other = make_user('other')

    def test_owner_can_read_secret_with_permanent_share(self):
        secret = new_secret(self.owner, share_with_owner=True)
        self.client.force_login(self.owner)
        resp = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.ALLOWED)

    def test_everyone_can_read_when_access_policy_any(self):
        secret = new_secret(self.owner, access_policy=AccessPolicy.ANY)
        self.client.force_login(self.other)
        resp = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.ALLOWED)

    def test_other_user_with_active_temporarily_share_can_read(self):
        secret = new_secret(self.owner, share_with_owner=True)
        SharedSecretData.objects.create(
            secret=secret,
            user=self.other,
            granted_by=self.owner,
            granted_until=now() + timedelta(weeks=1),
        )
        self.client.force_login(self.other)
        resp = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.TEMPORARILY_ALLOWED)

    def test_other_user_with_active_permanent_share_can_read(self):
        secret = new_secret(self.owner, share_with_owner=True)
        SharedSecretData.objects.create(secret=secret, user=self.other, granted_by=self.owner)
        self.client.force_login(self.other)
        resp = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.ALLOWED)

    def test_other_user_with_expired_share_cannot_read(self):
        secret = new_secret(self.owner, share_with_owner=True)
        SharedSecretData.objects.create(
            secret=secret,
            user=self.other,
            granted_by=self.owner,
            granted_until=now() - timedelta(days=1),
        )
        self.client.force_login(self.other)
        resp = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.NOT_ALLOWED)


@override_settings(**COMMON_OVERRIDES)
class SecretVisibilityPermissionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.other = make_user('other')

    def _get(self, user, secret):
        self.client.force_login(user)
        return self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]))

    def test_visible_but_not_readable_when_discoverable_and_no_share(self):
        secret = new_secret(self.owner, access_policy=AccessPolicy.DISCOVERABLE)
        resp = self._get(self.other, secret)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.NOT_ALLOWED)

    def test_hidden_not_visible_without_share(self):
        secret = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        resp = self._get(self.other, secret)
        self.assertEqual(resp.status_code, 404)

    def test_hidden_but_visible_with_share(self):
        secret = new_secret(self.owner)
        SharedSecretData.objects.create(secret=secret, user=self.other, granted_by=self.owner)

        resp = self._get(self.other, secret)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.ALLOWED)
