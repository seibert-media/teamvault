from copy import copy
from urllib.parse import urlencode

from django.test import Client, TestCase, override_settings
from django.urls import reverse

from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import (
    AccessPermissionTypes,
    SecretMetaSnapshot,
)
from .utils import COMMON_OVERRIDES, make_user, new_secret

RESTORE_URL_NAME = 'restore_secret_revision'


@override_settings(**COMMON_OVERRIDES)
class RestoreRevisionTests(TestCase):
    def setUp(self):
        # users
        self.owner = make_user('owner')
        self.su = make_user('root', superuser=True)
        self.bob = make_user('bob')

        # secret with 2 payload revisions + 1 meta snapshot
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.DISCOVERABLE)
        self.rev1 = self.secret.current_revision  # baseline
        self.secret.set_data(self.owner, {'password': 'v2'})  # second payload
        self.rev2 = self.secret.current_revision

        # pure metadata change after rev2
        self.secret.description = 'after‑v2'
        self.secret.save()
        payload = copy(self.rev2.get_data(self.owner))
        self.secret.set_data(self.owner, payload)
        self.meta_snap = SecretMetaSnapshot.objects.filter(revision=self.rev2).latest('created')

        self.client = Client()

    def _login(self, user):
        self.assertTrue(self.client.login(username=user.username, password='pw'))

    def _restore_url(self, secret, revision, meta_snap=None):
        if meta_snap:
            return (
                reverse(
                    RESTORE_URL_NAME,
                    args=(secret.id, revision.id),
                )
                + '?'
                + urlencode({'meta_snap': meta_snap.id})
            )
        return reverse(RESTORE_URL_NAME, args=(secret.id, revision.id))

    def test_superuser_can_restore_payload(self):
        """Superuser rolls back to rev1 – new revision becomes current."""
        self._login(self.su)

        pre_rev = self.secret.current_revision
        resp = self.client.post(self._restore_url(self.secret, self.rev1))
        self.assertEqual(resp.status_code, 302)  # redirected

        self.secret.refresh_from_db()
        self.assertNotEqual(self.secret.current_revision, pre_rev)
        self.assertEqual(
            self.secret.current_revision.plaintext_data_sha256,
            self.rev1.plaintext_data_sha256,
        )

    def test_superuser_can_restore_with_snapshot(self):
        """Restore rev2 + explicit metadata snapshot: metadata must match
        snapshot values (description in our setup)."""
        self._login(self.su)
        resp = self.client.post(self._restore_url(self.secret, self.rev2, self.meta_snap))
        self.assertEqual(resp.status_code, 302)

        self.secret.refresh_from_db()
        self.assertEqual(self.secret.description, self.meta_snap.description)

    def test_regular_user_cannot_restore(self):
        self._login(self.bob)

        # give bob read‑access but NOT superuser
        self.secret.share_data.create(user=self.bob)
        perm = self.secret.permission_checker(self.bob).is_readable()
        self.assertEqual(perm, AccessPermissionTypes.ALLOWED)

        resp = self.client.post(self._restore_url(self.secret, self.rev1))
        # view responds with redirect back to revision detail (status 302),
        # NOT with 200
        self.assertEqual(resp.status_code, 302)

        # current revision unchanged
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.current_revision, self.rev2)  # still latest
