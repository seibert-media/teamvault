import json
import time

from django.test import TestCase, override_settings
from django.urls import reverse

from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry
from teamvault.apps.secrets.services.revision import RevisionService
from ..utils import COMMON_OVERRIDES, OTP_SECRET, make_user, new_secret, otp_codes_during


@override_settings(**COMMON_OVERRIDES)
class OtpEndpointAuditTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.secret = new_secret(self.owner, name='otp-secret')
        RevisionService.save_payload(
            secret=self.secret,
            actor=self.owner,
            payload={
                'otp_key': OTP_SECRET,
                'digits': '6',
                'algorithm': 'SHA1',
            },
        )
        self.secret.refresh_from_db()
        self.client.force_login(self.owner)
        self.otp_url = reverse('api.secret-revision_otp', args=[self.secret.current_revision.hashid])

    def _secret_read_count(self) -> int:
        return LogEntry.objects.filter(
            actor=self.owner,
            secret=self.secret,
            secret_revision=self.secret.current_revision,
            category=AuditLogCategoryChoices.SECRET_READ,
        ).count()

    def _session_payload(self) -> str:
        return json.dumps(dict(self.client.session.items()))

    def _served_code(self) -> tuple[str, float, float]:
        started = time.time()
        response = self.client.get(self.otp_url)
        self.assertEqual(response.status_code, 200)
        return response.json(), started, time.time()

    def test_repeated_otp_refresh_logs_secret_read_once(self):
        self.assertEqual(self._secret_read_count(), 0)

        first = self.client.get(self.otp_url)
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json().isdigit())
        self.assertEqual(self._secret_read_count(), 1)

        second = self.client.get(self.otp_url)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(self._secret_read_count(), 1)

    def test_otp_request_writes_no_secret_material_into_the_session(self):
        self.client.get(self.otp_url)
        self.assertNotIn(OTP_SECRET, self._session_payload())

    def test_repeated_refreshes_keep_serving_correct_codes(self):
        self._served_code()
        code, started, finished = self._served_code()
        self.assertIn(code, otp_codes_during(OTP_SECRET, started, finished))
