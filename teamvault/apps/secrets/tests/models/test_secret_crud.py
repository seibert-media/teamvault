from base64 import b64encode

from django.test import TestCase, override_settings

from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.exceptions import PermissionError
from teamvault.apps.secrets.models import Secret, SecretRevision, SecretChange
from teamvault.apps.secrets.services.revision import RevisionService
from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class SecretModelCrudTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user("owner")

    def test_create_secret_with_password_payload_sets_current_revision_and_encrypts(self):
        s: Secret = new_secret(self.owner, name="pw")
        self.assertIsNotNone(s.current_revision)

        rev = s.current_revision
        # encrypted field is bytes and must not contain plaintext
        blob = rev.encrypted_data
        self.assertIsInstance(blob, (bytes, bytearray))
        self.assertNotIn(b"initial", blob)

    def test_read_returns_plaintext_and_updates_access_bookkeeping(self):
        s: Secret = new_secret(self.owner, name="readable")
        rev = s.current_revision

        # Creator is already in accessed_by from creation; count may already be 1
        before_last_read = rev.last_read
        before_access_count = rev.accessed_by.count()

        data = s.get_data(self.owner)
        self.assertIn("password", data)

        rev.refresh_from_db()
        # last_read bumped
        self.assertIsNotNone(rev.last_read)
        self.assertTrue(before_last_read is None or rev.last_read >= before_last_read)
        # creator remains in accessed_by; count stays >= previous
        self.assertGreaterEqual(rev.accessed_by.count(), before_access_count)
        self.assertIn(self.owner, rev.accessed_by.all())

    def test_update_creates_new_revision_and_keeps_history(self):
        s: Secret = new_secret(self.owner, name="update-me")
        rev_before = s.current_revision
        old_plain = rev_before.get_data(self.owner)

        # change password payload → new revision (different sha256)
        new_plain = dict(old_plain, password="changed-pass")
        RevisionService.save_payload(secret=s, actor=self.owner, payload=new_plain)

        s.refresh_from_db()
        rev_after = s.current_revision
        self.assertNotEqual(rev_after.id, rev_before.id)
        self.assertEqual(rev_after.get_data(self.owner)["password"], "changed-pass")

        # old revision remains addressable
        self.assertEqual(SecretRevision.objects.filter(id=rev_before.id, secret=s).count(), 1)

    def test_update_metadata_only_reuses_payload_but_emits_change(self):
        s: Secret = new_secret(self.owner, name="meta-only")
        rev_before = s.current_revision
        changes_before = SecretChange.objects.filter(secret=s).count()

        # simulate "metadata-only" change: modify secret fields, then write SAME payload
        s.description = "new desc"
        s.save(update_fields=["description"])
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

    def test_update_file_payload_roundtrip(self):
        s: Secret = new_secret(self.owner, name="filey")
        s.content_type = ContentType.FILE
        s.filename = "hello.bin"
        s.save(update_fields=["content_type", "filename"])

        raw = b"hello-\xf0\x9f\x9a\x80"
        RevisionService.save_payload(
            secret=s,
            actor=self.owner,
            payload={"file_content": b64encode(raw).decode("ascii")},
        )

        s.refresh_from_db()
        got = s.get_data(self.owner)
        self.assertIsInstance(got, (bytes, bytearray))
        self.assertEqual(got, raw)

    def test_delete_marks_secret_and_denies_visibility_and_read(self):
        s: Secret = new_secret(self.owner, name="todelete", access_policy=AccessPolicy.ANY)
        s.status = SecretStatus.DELETED
        s.save(update_fields=["status"])

        # get_data must raise (permission denied at read stage for deleted)
        with self.assertRaises(PermissionError):
            s.get_data(self.owner)

        # Deleted secrets are not returned by visibility helpers
        self.assertNotIn(s, Secret.get_all_visible_to_user(self.owner))

    def test_get_data_raises_without_access_on_hidden(self):
        s: Secret = new_secret(self.owner, name="hidden", access_policy=AccessPolicy.HIDDEN)
        # Another user without shares should not be able to read
        other = make_user("other")
        with self.assertRaises(PermissionError):
            s.get_data(other)
