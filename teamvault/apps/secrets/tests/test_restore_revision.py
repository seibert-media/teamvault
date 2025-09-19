from copy import copy
from urllib.parse import urlencode

from django.test import Client, TestCase, override_settings
from django.urls import reverse

from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
from teamvault.apps.secrets.models import (
    AccessPermissionTypes,
    SecretMeta,
    SecretChange,
)
from teamvault.apps.secrets.services.revision import RevisionService
from .utils import COMMON_OVERRIDES, make_user, new_secret

RESTORE_URL_NAME = 'restore_secret_revision'


@override_settings(**COMMON_OVERRIDES)
class RestoreRevisionTests(TestCase):
    def setUp(self):
        # users
        self.owner = make_user('owner')
        self.su = make_user('root', superuser=True)
        self.bob = make_user('bob')

        # secret with 2 payload revisions + 1 secret meta
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.DISCOVERABLE)
        self.rev1 = self.secret.current_revision  # baseline

        RevisionService.save_payload(
            secret=self.secret,
            actor=self.owner,
            payload={'password': 'v2'},
        )  # second payload
        self.rev2 = self.secret.current_revision

        # pure metadata change after rev2
        self.secret.description = 'after‑v2'
        self.secret.save()
        payload = copy(self.rev2.get_data(self.owner))
        RevisionService.save_payload(
            secret=self.secret,
            actor=self.owner,
            payload=payload,
        )
        self.meta = SecretMeta.objects.filter(revision=self.rev2).latest('created')

        self.client = Client()

    def _login(self, user):
        self.assertTrue(self.client.login(username=user.username, password='pw'))

    def _restore_url(self, secret, revision, meta=None):
        if meta:
            return (
                reverse(
                    RESTORE_URL_NAME,
                    args=(secret.hashid, revision.hashid),
                )
                + '?'
                + urlencode({'meta': meta.id})
            )
        return reverse(RESTORE_URL_NAME, args=(secret.hashid, revision.hashid))

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

    def test_superuser_can_restore_with_meta(self):
        """Restore rev2 + explicit metadata: metadata must match
        values (description in our setup)."""
        self._login(self.su)
        resp = self.client.post(self._restore_url(self.secret, self.rev2, self.meta))
        self.assertEqual(resp.status_code, 302)

        self.secret.refresh_from_db()
        self.assertEqual(self.secret.description, self.meta.description)
        # if metadata said NEEDS_CHANGING, restored secret must be NEEDS_CHANGING
        self.meta.status = SecretStatus.NEEDS_CHANGING
        self.meta.save(update_fields=['status'])
        resp = self.client.post(self._restore_url(self.secret, self.rev2, self.meta))
        self.assertEqual(resp.status_code, 302)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.status, 2)
        # latest change references the restored-from change (rev2 lineage)
        latest_change = SecretChange.objects.filter(secret=self.secret).latest('created')
        self.assertIsNotNone(latest_change.restored_from)
        self.assertEqual(latest_change.restored_from.revision_id, self.rev2.id)

    def test_regular_user_can_restore(self):
        self._login(self.bob)

        # give bob read‑access but NOT superuser
        self.secret.share_data.create(user=self.bob)
        perm = self.secret.permission_checker(self.bob).is_readable()
        self.assertEqual(perm, AccessPermissionTypes.ALLOWED)

        pre_rev = self.secret.current_revision
        resp = self.client.post(self._restore_url(self.secret, self.rev1))
        self.assertEqual(resp.status_code, 302)

        # current revision moved to restored payload
        self.secret.refresh_from_db()
        self.assertNotEqual(self.secret.current_revision, pre_rev)
        self.assertEqual(
            self.secret.current_revision.plaintext_data_sha256,
            self.rev1.plaintext_data_sha256,
        )

    def test_history_marks_needs_changing(self):
        # mark latest metadata as NEEDS_CHANGING
        meta_rec = self.meta
        meta_rec.status = 2
        meta_rec.save(update_fields=['status'])
        rows = RevisionService.get_revision_history(self.secret, self.owner)
        self.assertTrue(any(r.needs_changing for r in rows))
