from datetime import timedelta

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now

from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import SharedSecretData
from ..utils import COMMON_OVERRIDES, make_user, new_secret


def _share_delete_url(secret, share) -> str:
    return reverse('secrets.secret-share-delete', args=[secret.hashid, share.pk])


@override_settings(**COMMON_OVERRIDES)
class SecretShareDeleteViewTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.admin = make_user('admin', superuser=True)
        self.manager = make_user('manager')
        self.reader = make_user('reader')
        self.target = make_user('target')
        self.secret = new_secret(self.owner, name='view-share-secret', access_policy=AccessPolicy.HIDDEN)

    def test_temporary_reader_cannot_delete_another_users_expired_share(self):
        SharedSecretData.objects.create(
            secret=self.secret,
            user=self.reader,
            granted_by=self.owner,
            granted_until=now() + timedelta(days=1),
        )
        expired_share = SharedSecretData.objects.create(
            secret=self.secret,
            user=self.target,
            granted_by=self.owner,
            granted_until=now() - timedelta(days=1),
        )

        self.client.force_login(self.reader)
        response = self.client.delete(_share_delete_url(self.secret, expired_share))

        self.assertEqual(response.status_code, 403)
        self.assertTrue(SharedSecretData.objects.filter(pk=expired_share.pk).exists())

    def test_former_granter_cannot_delete_expired_share_without_current_share_access(self):
        manager_share = SharedSecretData.objects.create(
            secret=self.secret,
            user=self.manager,
            granted_by=self.owner,
        )
        expired_share = SharedSecretData.objects.create(
            secret=self.secret,
            user=self.target,
            granted_by=self.manager,
            granted_until=now() - timedelta(days=1),
        )
        manager_share.delete()

        self.client.force_login(self.manager)
        response = self.client.delete(_share_delete_url(self.secret, expired_share))

        self.assertEqual(response.status_code, 404)
        self.assertTrue(SharedSecretData.objects.filter(pk=expired_share.pk).exists())

    def test_superuser_can_delete_expired_self_share_without_read_access(self):
        expired_self_share = SharedSecretData.objects.create(
            secret=self.secret,
            user=self.admin,
            granted_by=self.owner,
            granted_until=now() - timedelta(days=1),
        )

        self.client.force_login(self.admin)
        response = self.client.delete(_share_delete_url(self.secret, expired_self_share))

        self.assertEqual(response.status_code, 200)
        self.assertFalse(SharedSecretData.objects.filter(pk=expired_self_share.pk).exists())
