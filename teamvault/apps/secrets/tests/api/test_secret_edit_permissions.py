from datetime import timedelta

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now
from rest_framework import status
from rest_framework.test import APIClient

from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
from teamvault.apps.secrets.models import SharedSecretData
from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class SecretEditPermissionAPITests(TestCase):
    """Same thing as the view's "SecretEditPermissionTests". Temp users shouldn't escalate privileges."""

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
        self.url = reverse('api.secret_detail', args=[self.secret.hashid])
        self.api_client = APIClient()

    def test_temporary_reader_can_still_read(self):
        self.api_client.force_authenticate(user=self.temp_reader)
        self.assertEqual(self.api_client.get(self.url).status_code, status.HTTP_200_OK)

    def test_temporary_reader_cannot_patch_access_policy(self):
        self.api_client.force_authenticate(user=self.temp_reader)
        resp = self.api_client.patch(self.url, {'access_policy': 'any'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.access_policy, AccessPolicy.HIDDEN)

    def test_temporary_reader_cannot_patch_payload(self):
        self.api_client.force_authenticate(user=self.temp_reader)
        revision_before = self.secret.current_revision_id
        resp = self.api_client.patch(self.url, {'secret_data': {'password': 'new'}}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.current_revision_id, revision_before)

    def test_temporary_reader_cannot_delete(self):
        self.api_client.force_authenticate(user=self.temp_reader)
        resp = self.api_client.delete(self.url)
        self.assertEqual(resp.status_code, status.HTTP_403_FORBIDDEN)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.status, SecretStatus.OK)

    def test_permanent_reader_can_patch_access_policy(self):
        self.api_client.force_authenticate(user=self.perm_reader)
        resp = self.api_client.patch(self.url, {'access_policy': 'any'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK, resp.data)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.access_policy, AccessPolicy.ANY)
