"""End-to-end coverage from the key a user pastes to the code we serve back.

The unit tests around OTP hand the payload to `RevisionService` already in its
stored shape, which only proves that generation works once storage is correct.
These tests cross the boundary instead: submit the key the way a user submits
it, then read a code out of the OTP endpoint and compare it against one
generated independently from the known seed.
"""

import time

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status

from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import Secret
from .utils import COMMON_OVERRIDES, OTP_SECRET, grouped_otp_secret, make_user, otp_codes_during

# This is how Google presents a key next to the QR code: Grouped into blocks and lowercased.
PASTED_OTP_KEY_DATA = (
    f'otpauth://totp/ACME:john?secret={grouped_otp_secret(secret=OTP_SECRET.lower())}'
    f'&digits=6&algorithm=SHA1&issuer=ACME'
)


@override_settings(**COMMON_OVERRIDES)
class OtpWebFormRoundTripTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.client.force_login(self.owner)

    def _add_password_secret(self, otp_key_data: str, name: str = 'otp-round-trip') -> Secret:
        response = self.client.post(
            reverse('secrets.secret-add', kwargs={'content_type': 'password'}),
            data={
                'name': name,
                'access_policy': AccessPolicy.DISCOVERABLE.value,
                'password': 'hunter2',
                'otp_key_data': otp_key_data,
            },
        )
        if response.status_code != status.HTTP_302_FOUND:
            self.fail(f'secret was not created: {response.context["form"].errors}')
        return Secret.objects.get(name=name)

    def test_pasted_key_round_trips_into_a_correct_code(self):
        secret = self._add_password_secret(PASTED_OTP_KEY_DATA)

        otp_url = reverse('api.secret-revision_otp', args=[secret.current_revision.hashid])
        started = time.time()
        response = self.client.get(otp_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.json(), otp_codes_during(OTP_SECRET, started, time.time()))

    def test_web_form_stores_a_parsed_otp_key(self):
        secret = self._add_password_secret(PASTED_OTP_KEY_DATA)

        payload = secret.current_revision.peek_data(self.owner)
        # Case is left as pasted; base32 decoding case-folds, so it round-trips either way.
        self.assertEqual(payload['otp_key'].upper(), OTP_SECRET)
        self.assertNotIn('otp_key_data', payload)

    def test_web_form_marks_the_revision_as_carrying_an_otp_key(self):
        secret = self._add_password_secret(PASTED_OTP_KEY_DATA)

        self.assertTrue(secret.current_revision.otp_key_set)
