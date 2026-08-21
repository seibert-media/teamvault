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
from rest_framework.test import APIClient

from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import Secret
from .utils import COMMON_OVERRIDES, OTP_SECRET, grouped_otp_secret, make_user, otp_codes_during

# This is how Google presents a key next to the QR code: Grouped into blocks and lowercased.
PASTED_OTP_KEY_DATA = (
    f'otpauth://totp/ACME:john?secret={grouped_otp_secret(secret=OTP_SECRET.lower())}'
    f'&digits=6&algorithm=SHA1&issuer=ACME'
)

MALFORMED_OTP_KEY_DATA = '?secret=not+a+valid+key!&digits=6'


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


@override_settings(**COMMON_OVERRIDES)
class OtpApiRoundTripTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.api_client = APIClient()
        self.api_client.force_authenticate(user=self.owner)

    def _create_password_secret(self, otp_key_data: str, name: str = 'api-otp'):
        return self.api_client.post(
            reverse('api.secret_list'),
            {
                'name': name,
                'access_policy': 'discoverable',
                'content_type': 'password',
                'secret_data': {'password': 'hunter2', 'otp_key_data': otp_key_data},
            },
            format='json',
        )

    def _created_secret(self, otp_key_data: str, name: str = 'api-otp') -> Secret:
        response = self._create_password_secret(otp_key_data, name)
        if response.status_code != status.HTTP_201_CREATED:
            self.fail(f'secret was not created ({response.status_code}): {response.data}')
        return Secret.objects.get(name=name)

    def test_created_secret_stores_a_parsed_otp_key(self):
        secret = self._created_secret(PASTED_OTP_KEY_DATA)

        payload = secret.current_revision.peek_data(self.owner)
        self.assertEqual(payload['otp_key'].upper(), OTP_SECRET)
        self.assertEqual(payload['digits'], '6')
        self.assertEqual(payload['algorithm'], 'SHA1')
        self.assertNotIn('otp_key_data', payload)

    def test_created_secret_marks_the_revision_as_carrying_an_otp_key(self):
        secret = self._created_secret(PASTED_OTP_KEY_DATA)

        self.assertTrue(secret.current_revision.otp_key_set)

    def test_created_secret_serves_a_correct_code(self):
        secret = self._created_secret(PASTED_OTP_KEY_DATA)

        otp_url = reverse('api.secret-revision_otp', args=[secret.current_revision.hashid])
        started = time.time()
        response = self.api_client.get(otp_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(response.json(), otp_codes_during(OTP_SECRET, started, time.time()))

    def test_updated_secret_stores_a_parsed_otp_key(self):
        secret = self._created_secret('', name='api-otp-later')

        response = self.api_client.patch(
            reverse('api.secret_detail', args=[secret.hashid]),
            {'secret_data': {'password': 'hunter2', 'otp_key_data': PASTED_OTP_KEY_DATA}},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, getattr(response, 'data', None))

        secret.refresh_from_db()
        payload = secret.current_revision.peek_data(self.owner)
        self.assertEqual(payload['otp_key'].upper(), OTP_SECRET)
        self.assertNotIn('otp_key_data', payload)
        self.assertTrue(secret.current_revision.otp_key_set)

    def test_malformed_otp_key_data_is_rejected_on_create(self):
        response = self._create_password_secret(MALFORMED_OTP_KEY_DATA)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Secret.objects.filter(name='api-otp').exists())

    def test_malformed_otp_key_data_is_rejected_on_update(self):
        secret = self._created_secret(PASTED_OTP_KEY_DATA, name='api-otp-keeps-key')
        original_revision = secret.current_revision

        response = self.api_client.patch(
            reverse('api.secret_detail', args=[secret.hashid]),
            {'secret_data': {'password': 'hunter2', 'otp_key_data': MALFORMED_OTP_KEY_DATA}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # A rejected update must not clobber the key the secret already had.
        secret.refresh_from_db()
        self.assertEqual(secret.current_revision, original_revision)
        self.assertEqual(secret.current_revision.peek_data(self.owner)['otp_key'].upper(), OTP_SECRET)
