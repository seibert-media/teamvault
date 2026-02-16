from django.test import TestCase, override_settings
from django.urls import reverse
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry
from teamvault.apps.secrets.services.revision import RevisionService

from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class OtpEndpointAuditTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.secret = new_secret(self.owner, name='otp-secret')
        RevisionService.save_payload(
            secret=self.secret,
            actor=self.owner,
            payload={
                'otp_key': 'JBSWY3DPEHPK3PXP',
                'digits': '6',
                'algorithm': 'SHA1',
            },
        )
        self.secret.refresh_from_db()
        self.client.force_login(self.owner)

    def _secret_read_count(self) -> int:
        return LogEntry.objects.filter(
            actor=self.owner,
            secret=self.secret,
            secret_revision=self.secret.current_revision,
            category=AuditLogCategoryChoices.SECRET_READ,
        ).count()

    def test_repeated_otp_refresh_logs_secret_read_once(self):
        otp_url = reverse('api.secret-revision_otp', args=[self.secret.current_revision.hashid])
        cache_key = f'otp_key_data-{self.secret.hashid}-{self.secret.current_revision_id}'

        self.assertEqual(self._secret_read_count(), 0)

        first = self.client.get(otp_url)
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json().isdigit())
        self.assertIn(cache_key, self.client.session)
        self.assertEqual(self._secret_read_count(), 1)

        second = self.client.get(otp_url)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(self._secret_read_count(), 1)
