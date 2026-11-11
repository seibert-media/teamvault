from django.test import TestCase, override_settings
from django.urls import reverse

from teamvault.apps.secrets.services.revision import RevisionService
from ..utils import COMMON_OVERRIDES, OTP_SECRET, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class RevisionDetailOtpTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.secret = new_secret(self.owner, payload={'password': 'v1'})
        self.without_otp = self.secret.current_revision
        RevisionService.save_payload(secret=self.secret, actor=self.owner, payload={'otp_key': OTP_SECRET})
        self.secret.refresh_from_db()
        self.with_otp = self.secret.current_revision
        RevisionService.save_payload(secret=self.secret, actor=self.owner, payload={'password': 'v2'})
        self.client.force_login(self.owner)

    def get(self, revision):
        response = self.client.get(reverse('secrets.revision-detail', args=[revision.hashid]))
        self.assertEqual(response.status_code, 200)
        return response

    def test_past_revision_with_otp_shows_codes_from_that_revision(self):
        response = self.get(self.with_otp)
        self.assertContains(response, 'id="otp-field"')
        self.assertContains(response, 'data-otp-enabled="true"')
        self.assertContains(response, reverse('api.secret-revision_data', args=[self.with_otp.hashid]))

    def test_past_revision_never_renders_the_otp_seed(self):
        self.assertNotContains(self.get(self.with_otp), OTP_SECRET)

    def test_past_revision_without_otp_has_no_otp_field(self):
        response = self.get(self.without_otp)
        self.assertNotContains(response, 'id="otp-field"')
        self.assertContains(response, 'data-otp-enabled="false"')
