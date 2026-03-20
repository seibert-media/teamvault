from datetime import timedelta

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.test import APIClient
from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import SharedSecretData

from ..utils import COMMON_OVERRIDES, make_user, new_secret


def _share_list_url(secret) -> str:
    return reverse('api.secret_share', args=[secret.hashid])


def _share_detail_url(secret, share) -> str:
    return reverse('api.secret_share_detail', args=[secret.hashid, share.pk])


@override_settings(**COMMON_OVERRIDES)
class SecretShareApiTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.admin = make_user('admin', superuser=True)
        self.manager = make_user('manager')
        self.reader = make_user('reader')
        self.target = make_user('target')
        self.secret = new_secret(self.owner, name='api-share-secret', access_policy=AccessPolicy.HIDDEN)
        self.api_client = APIClient()

    def test_api_allows_reshare_after_expiry(self):
        SharedSecretData.objects.create(
            secret=self.secret,
            user=self.target,
            granted_by=self.owner,
            granted_until=now() - timedelta(days=1),
        )

        self.api_client.force_authenticate(user=self.owner)
        response = self.api_client.post(
            _share_list_url(self.secret),
            data={
                'user': self.target.username,
                'group': None,
                'grant_description': 're-share',
                'granted_until': (now() + timedelta(days=7)).isoformat(),
            },
            format='json',
        )

        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(
            SharedSecretData.objects.filter(secret=self.secret, user=self.target).count(),
            1,
        )

    def test_api_allows_superuser_to_delete_expired_self_share_and_reshare(self):
        expired_self_share = SharedSecretData.objects.create(
            secret=self.secret,
            user=self.admin,
            granted_by=self.owner,
            granted_until=now() - timedelta(days=1),
        )

        self.api_client.force_authenticate(user=self.admin)
        delete_response = self.api_client.delete(_share_detail_url(self.secret, expired_self_share))

        self.assertEqual(delete_response.status_code, 204, delete_response.data)
        self.assertFalse(SharedSecretData.objects.filter(pk=expired_self_share.pk).exists())

        create_response = self.api_client.post(
            _share_list_url(self.secret),
            data={
                'user': self.admin.username,
                'group': None,
                'grant_description': 'renew self-share',
                'granted_until': (now() + timedelta(days=7)).isoformat(),
            },
            format='json',
        )

        self.assertEqual(create_response.status_code, 201, create_response.data)
        self.assertEqual(
            SharedSecretData.objects.filter(secret=self.secret, user=self.admin).count(),
            1,
        )
