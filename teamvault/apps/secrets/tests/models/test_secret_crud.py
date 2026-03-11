from base64 import b64encode
from unittest import mock

from django.test import TestCase, override_settings

from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.exceptions import PermissionError
from teamvault.apps.secrets.models import Secret, SecretChange, SecretRevision
from teamvault.apps.secrets.services.revision import RevisionService
from teamvault.apps.secrets.utils import copy_meta_from_secret
from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class SecretModelCrudTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')

    def test_create_secret_with_password_payload_sets_current_revision_and_encrypts(self):
        s: Secret = new_secret(self.owner, name='pw')
        self.assertIsNotNone(s.current_revision)

        rev = s.current_revision
        # encrypted field is bytes and must not contain plaintext
        blob = rev.encrypted_data
        self.assertIsInstance(blob, (bytes, bytearray))
        self.assertNotIn(b'initial', blob)

    def test_read_returns_plaintext_and_updates_access_bookkeeping(self):
        s: Secret = new_secret(self.owner, name='readable')
        rev = s.current_revision

        # Creator is already in accessed_by from creation; count may already be 1
        before_last_read = rev.last_read
        before_access_count = rev.accessed_by.count()

        data = s.get_data(self.owner)
        self.assertIn('password', data)

        rev.refresh_from_db()
        # last_read bumped
        self.assertIsNotNone(rev.last_read)
        self.assertTrue(before_last_read is None or rev.last_read >= before_last_read)
        # creator remains in accessed_by; count stays >= previous
        self.assertGreaterEqual(rev.accessed_by.count(), before_access_count)
        self.assertIn(self.owner, rev.accessed_by.all())

    def test_update_creates_new_revision_and_keeps_history(self):
        s: Secret = new_secret(self.owner, name='update-me')
        rev_before = s.current_revision
        old_plain = rev_before.get_data(self.owner)

        # change password payload → new revision (different sha256)
        new_plain = dict(old_plain, password='changed-pass')
        RevisionService.save_payload(secret=s, actor=self.owner, payload=new_plain)

        s.refresh_from_db()
        rev_after = s.current_revision
        self.assertNotEqual(rev_after.id, rev_before.id)
        self.assertEqual(rev_after.get_data(self.owner)['password'], 'changed-pass')

        # old revision remains addressable
        self.assertEqual(SecretRevision.objects.filter(id=rev_before.id, secret=s).count(), 1)

    def test_update_metadata_only_reuses_payload_but_emits_change(self):
        s: Secret = new_secret(self.owner, name='meta-only')
        rev_before = s.current_revision
        changes_before = SecretChange.objects.filter(secret=s).count()

        # simulate "metadata-only" change: modify secret fields, then write SAME payload
        s.description = 'new desc'
        s.save(update_fields=['description'])
        payload_same = rev_before.get_data(self.owner)
        RevisionService.save_payload(secret=s, actor=self.owner, payload=payload_same)

        s.refresh_from_db()
        rev_after = s.current_revision

        # Payload is identical → revision object may be reused (same sha / same row)
        self.assertEqual(rev_after.id, rev_before.id)

        # But a new SecretChange snapshot should be recorded
        self.assertGreater(
            SecretChange.objects.filter(secret=s).count(),
            changes_before,
        )

    def test_noop_payload_edit_does_not_emit_change(self):
        s: Secret = new_secret(self.owner, name='noop')
        s.refresh_from_db()
        changes_before = SecretChange.objects.filter(secret=s).count()
        last_changed_before = s.last_changed
        last_read_before = s.last_read

        payload_same = s.current_revision.peek_data(self.owner)
        RevisionService.save_payload(secret=s, actor=self.owner, payload=payload_same)

        s.refresh_from_db()
        self.assertEqual(SecretChange.objects.filter(secret=s).count(), changes_before)
        self.assertEqual(s.last_changed, last_changed_before)
        self.assertEqual(s.last_read, last_read_before)

    def test_parent_re_fetched_after_secret_update(self):
        s: Secret = new_secret(self.owner, name='linear-history')
        concurrent_actor = make_user('concurrent')
        new_payload = {'password': 'v2'}

        original_save = Secret.save

        def wrapped_save(self, *args, **kwargs):
            result = original_save(self, *args, **kwargs)
            if self.pk == s.pk and not wrapped_save.injected:
                wrapped_save.injected = True
                parent = SecretChange.objects.filter(secret=self).order_by('-created').first()
                SecretChange.objects.create(
                    secret=self,
                    revision=self.current_revision,
                    actor=concurrent_actor,
                    parent=parent,
                    **copy_meta_from_secret(self),
                )
            return result

        wrapped_save.injected = False

        with mock.patch.object(Secret, 'save', wrapped_save):
            RevisionService.save_payload(secret=s, actor=self.owner, payload=new_payload)

        changes = list(SecretChange.objects.filter(secret=s).order_by('created'))
        concurrent_change = changes[-2]
        head = changes[-1]
        self.assertEqual(head.parent_id, concurrent_change.id)

    def test_update_file_payload_roundtrip(self):
        s: Secret = new_secret(self.owner, name='filey')
        s.content_type = ContentType.FILE
        s.filename = 'hello.bin'
        s.save(update_fields=['content_type', 'filename'])

        raw = b'hello-\xf0\x9f\x9a\x80'
        RevisionService.save_payload(
            secret=s,
            actor=self.owner,
            payload={'file_content': b64encode(raw).decode('ascii')},
        )

        s.refresh_from_db()
        got = s.get_data(self.owner)
        self.assertIsInstance(got, (bytes, bytearray))
        self.assertEqual(got, raw)

    def test_otp_only_update_creates_new_revision(self):
        s: Secret = new_secret(self.owner, name='otp-add')
        rev_before = s.current_revision
        self.assertFalse(rev_before.otp_key_set)

        changes_before = SecretChange.objects.filter(secret=s).count()

        # OTP-only update: omit password, keep existing via merge logic.
        RevisionService.save_payload(
            secret=s,
            actor=self.owner,
            payload={
                'otp_key': 'JBSWY3DPEHPK3PXP',
                'digits': '6',
                'algorithm': 'SHA1',
            },
        )

        s.refresh_from_db()
        rev_after = s.current_revision
        self.assertNotEqual(rev_after.id, rev_before.id)
        self.assertTrue(rev_after.otp_key_set)
        self.assertEqual(rev_after.get_data(self.owner)['otp_key'], 'JBSWY3DPEHPK3PXP')

        # Re-saving identical OTP-only payload should be a no-op.
        RevisionService.save_payload(
            secret=s,
            actor=self.owner,
            payload={
                'otp_key': 'JBSWY3DPEHPK3PXP',
                'digits': '6',
                'algorithm': 'SHA1',
            },
        )
        self.assertEqual(SecretChange.objects.filter(secret=s).count(), changes_before + 1)

    def test_delete_marks_secret_and_denies_visibility_and_read(self):
        s: Secret = new_secret(self.owner, name='todelete', access_policy=AccessPolicy.ANY)
        s.status = SecretStatus.DELETED
        s.save(update_fields=['status'])

        # get_data must raise (permission denied at read stage for deleted)
        with self.assertRaises(PermissionError):
            s.get_data(self.owner)

        # Deleted secrets are not returned by visibility helpers
        self.assertNotIn(s, Secret.get_all_visible_to_user(self.owner))

    def test_get_data_raises_without_access_on_hidden(self):
        s: Secret = new_secret(self.owner, name='hidden', access_policy=AccessPolicy.HIDDEN)
        # Another user without shares should not be able to read
        other = make_user('other')
        with self.assertRaises(PermissionError):
            s.get_data(other)
