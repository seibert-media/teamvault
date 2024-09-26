import logging

from django.contrib.auth.models import Group, User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.test import override_settings
from django.test.utils import ignore_warnings
from django.urls import reverse

from teamvault.apps.secrets.models import Secret
from teamvault.apps.secrets.tests.base import BaseTestCase
from teamvault.apps.secrets.utils import serialize_add_edit_data

# Django tries to access staticfiles during tests, which we don't need
ignore_warnings(message="No directory at", module="django.core.handlers.base").enable()

logger = logging.getLogger(__name__)

TEST_SETTINGS_OVERRIDES = {
    'AUTHENTICATION_BACKENDS': ('django.contrib.auth.backends.ModelBackend',)
}

TEST_SECRET_DEFAULT_NAME = 'Test Secret'
TEST_SECRET_DATA = {
    'name': TEST_SECRET_DEFAULT_NAME,
    'description': 'A test secret',
    'username': 'testuser',
    'password': 'password',
    'access_policy': Secret.ACCESS_POLICY_DISCOVERABLE,
    'url': 'http://example.com',
    'otp_key_data': '',
}


@override_settings(**TEST_SETTINGS_OVERRIDES)
class SecretIntegrationTests(BaseTestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='password')
        self.superuser = User.objects.create_superuser(username='admin', password='password')
        self.group = Group.objects.create(name='testgroup')
        self.user.groups.add(self.group)
        self.client.login(username='testuser', password='password')

    def _create_test_secret(self, name='Test Secret', created_by=None, content_type=Secret.CONTENT_PASSWORD) -> Secret:
        """
        Handles creating a secret with the correct content type and created_by,
         sets the revision and shares it with the created user
        """
        secret = Secret.objects.create(
            name=name,
            content_type=content_type,
            created_by=created_by or self.user,
        )
        plaintext_data = serialize_add_edit_data(TEST_SECRET_DATA, secret)
        secret.set_data(self.user, plaintext_data, skip_access_check=True)
        secret.share_data.create(user=created_by or self.user)
        return secret

    def _create_test_secret_via_frontend(self) -> tuple[HttpResponse, Secret]:
        # Creating a secret via the frontend handles automatic sharing and setting revisions correctly
        response = self.client.post(
            reverse('secrets.secret-add', kwargs={'content_type': 'password'}),
            TEST_SECRET_DATA,
            follow=True
        )
        secret = Secret.objects.filter(name=TEST_SECRET_DEFAULT_NAME).last()
        return response, secret

    def test_create_secret(self):
        response, secret = self._create_test_secret_via_frontend()
        self.assertEqual(response.status_code, 200)
        self.assertFormValid(response)
        self.assertTrue(secret)

    def test_read_secret(self):
        _, secret = self._create_test_secret_via_frontend()
        response = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'You are not allowed to read this secret')

    def test_update_secret(self):
        _, secret = self._create_test_secret_via_frontend()
        update_data = TEST_SECRET_DATA.copy()
        update_data['description'] = 'Updated description'
        response = self.client.post(
            reverse('secrets.secret-edit', args=[secret.hashid]),
            update_data,
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        secret.refresh_from_db()
        self.assertEqual(secret.description, 'Updated description')

    def test_delete_secret(self):
        _, secret = self._create_test_secret_via_frontend()
        response: HttpResponse = self.client.post(reverse('secrets.secret-delete', args=[secret.hashid]), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFormValid(response)
        secret.refresh_from_db()
        self.assertTrue(secret.status == Secret.STATUS_DELETED)

    def test_delete_permission_denied_for_non_superuser(self):
        secret = self._create_test_secret(created_by=self.superuser)
        with self.assertRaises(PermissionDenied):
            secret.check_delete_access(self.user)
            response: HttpResponse = self.client.post(
                reverse('secrets.secret-delete', args=[secret.hashid]),
                follow=True
            )
            self.assertEqual(response.status_code, 403)

        secret.refresh_from_db()
        self.assertFalse(secret.status == Secret.STATUS_DELETED)

    def test_read_permission_denied_for_non_superuser(self):
        secret = self._create_test_secret(created_by=self.superuser)
        self.assertRaises(PermissionDenied, secret.check_read_access, self.user)
        response: HttpResponse = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]), follow=True)
        self.assertContains(response, 'You are not allowed to read this secret')

    def test_superuser_can_access_secret(self):
        secret = self._create_test_secret(created_by=self.superuser)
        self.assertTrue(secret.check_read_access(self.superuser))
        self.client.login(username='admin', password='password')
        response: HttpResponse = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]), follow=True)
        self.assertNotContains(response, 'You are not allowed to read this secret')
