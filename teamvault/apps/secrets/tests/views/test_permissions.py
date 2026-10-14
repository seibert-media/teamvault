from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now

from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
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


@override_settings(**COMMON_OVERRIDES)
class SecretEditPermissionTests(TestCase):
    """
    A temporary share should only grant the user read permissions.
    Changing metadata like "access_policy" or deleting the secret altogether
    requires permanent access, otherwise a user could make the secret public and/or
    share it to themselves.
    """

    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.temp_reader = make_user('temp_reader')
        cls.perm_reader = make_user('perm_reader')

    def setUp(self):
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        SharedSecretData.objects.create(
            secret=self.secret,
            user=self.temp_reader,
            granted_by=self.owner,
            granted_until=now() + timedelta(days=1),
        )
        SharedSecretData.objects.create(secret=self.secret, user=self.perm_reader, granted_by=self.owner)
        self.edit_url = reverse('secrets.secret-edit', args=[self.secret.hashid])
        self.delete_url = reverse('secrets.secret-delete', args=[self.secret.hashid])

    def _post_edit(self, user, access_policy):
        self.client.force_login(user)
        return self.client.post(
            self.edit_url,
            {'name': self.secret.name, 'access_policy': int(access_policy), 'needs_changing_on_leave': 'on'},
        )

    def test_temporary_reader_cannot_open_edit_form(self):
        self.client.force_login(self.temp_reader)
        self.assertEqual(self.client.get(self.edit_url).status_code, 403)

    def test_temporary_reader_cannot_change_access_policy(self):
        resp = self._post_edit(self.temp_reader, AccessPolicy.ANY)
        self.assertEqual(resp.status_code, 403)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.access_policy, AccessPolicy.HIDDEN)

    def test_permanent_reader_can_change_access_policy(self):
        resp = self._post_edit(self.perm_reader, AccessPolicy.ANY)
        self.assertEqual(resp.status_code, 302, getattr(resp, 'context', None) and resp.context.get('form'))
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.access_policy, AccessPolicy.ANY)

    def test_temporary_reader_cannot_delete(self):
        self.client.force_login(self.temp_reader)
        resp = self.client.post(self.delete_url)
        self.assertEqual(resp.status_code, 403)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.status, SecretStatus.OK)

    def test_temporary_reader_sees_edit_and_delete_disabled(self):
        self.client.force_login(self.temp_reader)
        resp = self.client.get(reverse('secrets.secret-detail', args=[self.secret.hashid]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.context['readable'], AccessPermissionTypes.TEMPORARILY_ALLOWED)
        self.assertEqual(resp.context['editable'], AccessPermissionTypes.NOT_ALLOWED)
