from base64 import b64encode

from django.test import TestCase, override_settings
from django.urls import reverse

from teamvault.apps.secrets.enums import ContentType
from teamvault.apps.secrets.models import Secret, SecretRevision  # noqa: TC001
from teamvault.apps.secrets.services.revision import RevisionService
from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class EncryptionViewConstraintsTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = make_user('alice')
        cls.pass_secret: Secret = new_secret(cls.user, name='pw-secret')
        cls.file_bytes = b'hello-from-bytes-\xf0\x9f\x9a\x80'
        cls.file_secret: Secret = new_secret(cls.user, name='file-secret')
        cls.file_secret.content_type = ContentType.FILE
        cls.file_secret.filename = 'hello.bin'
        cls.file_secret.save(update_fields=['content_type', 'filename'])
        RevisionService.save_payload(
            secret=cls.file_secret,
            actor=cls.user,
            payload={'file_content': b64encode(cls.file_bytes).decode('ascii')},
        )

    def test_secret_detail_page_never_leaks_plaintext(self):
        """The HTML detail view must not contain the decrypted payload text."""
        self.client.force_login(self.user)
        url = reverse('secrets.secret-detail', args=[self.pass_secret.hashid])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        plaintext = self.pass_secret.current_revision.get_data(self.user)['password'].encode('utf-8')
        self.assertNotIn(plaintext, resp.content)

    def test_api_revision_data_decrypts_and_updates_last_read_and_accessed_by(self):
        """Calling the data API decrypts payload and updates bookkeeping."""
        self.client.force_login(self.user)
        rev: SecretRevision = self.pass_secret.current_revision

        pre_last_read = rev.last_read
        pre_access = rev.accessed_by.count()

        api_url = reverse('api.secret-revision_data', kwargs={'hashid': rev.hashid})
        resp = self.client.get(api_url)
        self.assertEqual(resp.status_code, 200)

        data = resp.json()
        self.assertEqual(data.get('password'), 'initial‑pw')

        rev.refresh_from_db()
        self.assertIsNotNone(rev.last_read)
        self.assertTrue(pre_last_read is None or rev.last_read >= pre_last_read)
        self.assertGreaterEqual(rev.accessed_by.count(), pre_access)
        self.assertIn(self.user, rev.accessed_by.all())

    def test_secret_download_returns_file_bytes_with_attachment_headers(self):
        """
        Should return the exact file bytes as an attachment.
        """
        self.client.force_login(self.user)
        url = reverse('secrets.secret-download', kwargs={'hashid': self.file_secret.hashid})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)

        cd = resp.headers.get('Content-Disposition', '')
        self.assertIn('attachment;', cd)
        self.assertIn('filename*=', cd)
        self.assertEqual(resp.content, self.file_bytes)

    def test_secret_list_page_does_not_render_plaintext_for_file_secret(self):
        """List page must not inline decrypted bytes."""
        self.client.force_login(self.user)
        url = reverse('secrets.secret-list')
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(self.file_bytes, resp.content)

    def test_secret_revisions_page_loads_without_plaintext(self):
        """History page renders without leaking plaintext."""
        self.client.force_login(self.user)
        url = reverse('secrets.secret-revisions', args=[self.pass_secret.hashid])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b'initial-pw', resp.content)
