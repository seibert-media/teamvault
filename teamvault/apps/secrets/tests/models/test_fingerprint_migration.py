from importlib import import_module
from json import dumps
from types import SimpleNamespace

from cryptography.fernet import Fernet
from django.apps import apps as django_apps
from django.conf import settings
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from teamvault.apps.audit.models import LogEntry
from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.fingerprint import payload_fingerprint
from teamvault.apps.secrets.models import Secret, SecretChange, SecretRevision
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user
from teamvault.apps.secrets.utils import copy_meta_from_secret

migration_module = import_module('teamvault.apps.secrets.migrations.0042_rehash_revision_fingerprints')


class AppRegistryStub:
    @staticmethod
    def get_model(app_label, model_name):
        return django_apps.get_model(app_label, model_name)


class SchemaEditorStub:
    connection = SimpleNamespace(alias='default')


@override_settings(**COMMON_OVERRIDES)
class RehashRevisionFingerprintsTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.reader = make_user('reader')
        self.secret = Secret.objects.create(
            name='Legacy',
            created_by=self.owner,
            content_type=ContentType.PASSWORD,
            access_policy=AccessPolicy.DISCOVERABLE,
            status=SecretStatus.OK,
        )

    def _legacy_revision(self, payload: dict, legacy_hash: str) -> SecretRevision:
        encrypted = Fernet(settings.TEAMVAULT_SECRET_KEY).encrypt(dumps(payload).encode())
        return SecretRevision.objects.create(
            secret=self.secret,
            encrypted_data=encrypted,
            plaintext_data_sha256=legacy_hash,
            set_by=self.owner,
        )

    @staticmethod
    def _migrate():
        migration_module.rehash_revision_fingerprints(AppRegistryStub(), SchemaEditorStub())

    def test_rewrites_hash_to_keyed_fingerprint(self):
        payload = {'password': 'hunter2'}
        revision = self._legacy_revision(payload, 'legacy-sha256')

        self._migrate()

        revision.refresh_from_db()
        self.assertEqual(revision.plaintext_data_sha256, payload_fingerprint(self.secret.id, payload))

    def test_merges_revisions_whose_plaintext_was_hashed_differently(self):
        payload = {'password': 'hunter2'}
        original = self._legacy_revision(payload, 'sha256-of-bare-password')
        duplicate = self._legacy_revision(payload, 'sha256-of-json-payload')
        unrelated = self._legacy_revision({'password': 'other'}, 'sha256-of-other')
        duplicate.accessed_by.add(self.reader)
        change_on_duplicate = SecretChange.objects.create(
            secret=self.secret, revision=duplicate, actor=self.owner, **copy_meta_from_secret(self.secret)
        )
        log_on_duplicate = LogEntry.objects.create(secret=self.secret, secret_revision=duplicate, actor=self.owner)
        self.secret.current_revision = duplicate
        self.secret.save()

        self._migrate()

        self.assertFalse(SecretRevision.objects.filter(pk=duplicate.pk).exists())
        self.assertTrue(SecretRevision.objects.filter(pk=unrelated.pk).exists())
        original.refresh_from_db()
        self.assertEqual(original.plaintext_data_sha256, payload_fingerprint(self.secret.id, payload))
        self.assertIn(self.reader, original.accessed_by.all())
        change_on_duplicate.refresh_from_db()
        self.assertEqual(change_on_duplicate.revision_id, original.pk)
        log_on_duplicate.refresh_from_db()
        self.assertEqual(log_on_duplicate.secret_revision_id, original.pk)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.current_revision_id, original.pk)

    def test_rewrites_a_batch_of_revisions_with_one_update_statement(self):
        for index in range(3):
            self._legacy_revision({'password': f'pw-{index}'}, f'legacy-{index}')

        with CaptureQueriesContext(connection) as captured:
            self._migrate()

        updates = [
            q['sql'] for q in captured.captured_queries if q['sql'].startswith('UPDATE "secrets_secretrevision"')
        ]
        self.assertEqual(len(updates), 1)
