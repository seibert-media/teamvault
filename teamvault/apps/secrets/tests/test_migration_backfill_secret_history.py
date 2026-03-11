from datetime import timedelta
from importlib import import_module
from types import SimpleNamespace

from django.apps import apps as django_apps
from django.test import TestCase, override_settings
from django.utils.timezone import now

from teamvault.apps.audit.models import LogEntry
from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret, SecretChange, SecretRevision
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user

migration_module = import_module('teamvault.apps.secrets.migrations.0038_secretrevision_last_read_secretchange')


class AppRegistryStub:
    @staticmethod
    def get_model(app_label, model_name):
        return django_apps.get_model(app_label, model_name)


class SchemaEditorStub:
    def __init__(self, alias='default'):
        self.connection = SimpleNamespace(alias=alias)


@override_settings(**COMMON_OVERRIDES)
class SecretHistoryBackfillTests(TestCase):
    maxDiff = None

    @staticmethod
    def _call_migration():
        SecretChange.objects.all().delete()
        migration_module.backfill_secret_changes(AppRegistryStub(), SchemaEditorStub())

    @staticmethod
    def _make_secret_with_revisions():
        owner = make_user('owner')
        secret = Secret.objects.create(
            name='Legacy Secret',
            created_by=owner,
            content_type=ContentType.PASSWORD,
            access_policy=AccessPolicy.DISCOVERABLE,
            status=SecretStatus.OK,
        )

        base_ts = now() - timedelta(days=3)
        Secret.objects.filter(pk=secret.pk).update(created=base_ts)
        secret.refresh_from_db()

        rev1 = SecretRevision.objects.create(
            secret=secret,
            encrypted_data=b'{}',
            otp_key_set=False,
            length=0,
            plaintext_data_sha256='hash-one',
            set_by=owner,
        )
        rev2 = SecretRevision.objects.create(
            secret=secret,
            encrypted_data=b'{}',
            otp_key_set=False,
            length=0,
            plaintext_data_sha256='hash-two',
            set_by=owner,
        )

        SecretRevision.objects.filter(pk=rev1.pk).update(created=base_ts + timedelta(hours=1))
        SecretRevision.objects.filter(pk=rev2.pk).update(created=base_ts + timedelta(hours=2))
        rev1.refresh_from_db()
        rev2.refresh_from_db()

        secret.current_revision = rev2
        secret.last_changed = rev2.created
        secret.save(update_fields=['current_revision', 'last_changed'])
        return secret, owner, rev1, rev2

    def test_backfill_creates_changes_from_logs_and_revisions(self):
        secret, owner, rev1, rev2 = self._make_secret_with_revisions()

        log_time = rev2.created + timedelta(minutes=15)
        log = LogEntry.objects.create(
            actor=owner,
            category='secret_changed',
            message='owner updated payload',
            secret=secret,
            secret_revision=rev2,
        )
        LogEntry.objects.filter(pk=log.pk).update(time=log_time)
        log.refresh_from_db()

        self._call_migration()

        changes = list(SecretChange.objects.filter(secret=secret).order_by('created'))
        self.assertEqual(len(changes), 2)

        first, second = changes
        self.assertEqual(first.revision_id, rev1.id)
        self.assertIsNone(first.parent_id)
        self.assertEqual(first.actor_id, owner.id)
        self.assertEqual(first.created, rev1.created)
        self.assertTrue(first.hashid)

        self.assertEqual(second.revision_id, rev2.id)
        self.assertEqual(second.parent_id, first.id)
        self.assertEqual(second.actor_id, owner.id)
        self.assertEqual(second.created, log_time)
        self.assertTrue(second.hashid)

    def test_backfill_marks_restored_changes(self):
        secret, owner, rev1, rev2 = self._make_secret_with_revisions()

        log1 = LogEntry.objects.create(
            actor=owner,
            category='secret_changed',
            message='initial payload',
            secret=secret,
            secret_revision=rev1,
        )
        LogEntry.objects.filter(pk=log1.pk).update(time=rev1.created)

        log2 = LogEntry.objects.create(
            actor=owner,
            category='secret_changed',
            message='owner updated payload',
            secret=secret,
            secret_revision=rev2,
        )
        LogEntry.objects.filter(pk=log2.pk).update(time=rev2.created)

        restore_time = rev2.created + timedelta(hours=6)
        log3 = LogEntry.objects.create(
            actor=owner,
            category='secret_restored',
            message='rolled back payload',
            secret=secret,
            secret_revision=rev1,
        )
        LogEntry.objects.filter(pk=log3.pk).update(time=restore_time)

        secret.current_revision = rev1
        secret.last_changed = restore_time
        secret.save(update_fields=['current_revision', 'last_changed'])

        self._call_migration()

        changes = list(SecretChange.objects.filter(secret=secret).order_by('created'))
        self.assertEqual(len(changes), 3)

        first, second, third = changes
        self.assertEqual(third.revision_id, rev1.id)
        self.assertEqual(third.parent_id, second.id)
        self.assertEqual(third.restored_from_id, first.id)
        self.assertEqual(third.created, restore_time)
        self.assertTrue(all(ch.hashid for ch in changes))
