"""Coverage for the digest algorithm stored alongside an OTP seed.

The seed alone does not determine the code: a SHA256 or SHA512 QR code produces
completely different digits from the same seed. These tests compare the code we
serve against one generated independently with the expected digest, so a silent
fallback to SHA1 shows up as a wrong code rather than as no error at all.
"""

import hashlib
import time

from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from teamvault.apps.secrets.enums import AccessPolicy, ContentType
from teamvault.apps.secrets.models import Secret
from .utils import COMMON_OVERRIDES, OTP_SECRET, make_user, new_secret, otp_codes_during

DIGESTS = {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512}


def otp_key_data(algorithm: str) -> str:
    return f'otpauth://totp/ACME:john?secret={OTP_SECRET}&digits=6&algorithm={algorithm}&issuer=ACME'


@override_settings(**COMMON_OVERRIDES)
class OtpAlgorithmCodeGenerationTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.client.force_login(self.owner)

    def _add_password_secret(self, algorithm: str, name: str) -> Secret:
        response = self.client.post(
            reverse('secrets.secret-add', kwargs={'content_type': 'password'}),
            data={
                'name': name,
                'access_policy': AccessPolicy.DISCOVERABLE.value,
                'password': 'hunter2',
                'otp_key_data': otp_key_data(algorithm),
            },
        )
        if response.status_code != status.HTTP_302_FOUND:
            self.fail(f'secret was not created: {response.context["form"].errors}')
        return Secret.objects.get(name=name)

    def _served_code(self, secret: Secret) -> tuple[str, float, float]:
        started = time.time()
        response = self.client.get(reverse('api.secret-revision_otp', args=[secret.current_revision.hashid]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.json(), started, time.time()

    def test_sha256_secret_serves_a_sha256_code(self):
        secret = self._add_password_secret('SHA256', name='otp-sha256')

        code, started, finished = self._served_code(secret)

        self.assertIn(code, otp_codes_during(OTP_SECRET, started, finished, digest=hashlib.sha256))

    def test_sha512_secret_serves_a_sha512_code(self):
        secret = self._add_password_secret('SHA512', name='otp-sha512')

        code, started, finished = self._served_code(secret)

        self.assertIn(code, otp_codes_during(OTP_SECRET, started, finished, digest=hashlib.sha512))

    def test_lowercase_algorithm_is_honoured(self):
        secret = self._add_password_secret('sha256', name='otp-lowercase')

        code, started, finished = self._served_code(secret)

        self.assertIn(code, otp_codes_during(OTP_SECRET, started, finished, digest=hashlib.sha256))

    def test_revision_without_a_stored_algorithm_still_serves_sha1(self):
        # Revisions written before the algorithm was captured carry only the seed.
        secret = new_secret(
            self.owner,
            content_type=ContentType.PASSWORD,
            payload={'password': 'hunter2', 'otp_key': OTP_SECRET},
            name='otp-legacy-revision',
        )

        code, started, finished = self._served_code(secret)

        self.assertIn(code, otp_codes_during(OTP_SECRET, started, finished, digest=hashlib.sha1))

    def test_revision_with_an_unsupported_stored_algorithm_is_refused(self):
        # Only reachable for revisions written before unknown algorithms were rejected;
        # serving a code that cannot work is worse than refusing to serve one.
        secret = new_secret(
            self.owner,
            content_type=ContentType.PASSWORD,
            payload={'password': 'hunter2', 'otp_key': OTP_SECRET, 'algorithm': 'SHA3'},
            name='otp-unsupported-revision',
        )

        response = self.client.get(reverse('api.secret-revision_otp', args=[secret.current_revision.hashid]))

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_second_request_serves_a_sha256_code_from_the_cache(self):
        secret = self._add_password_secret('SHA256', name='otp-sha256-cached')
        self._served_code(secret)

        code, started, finished = self._served_code(secret)

        self.assertIn(code, otp_codes_during(OTP_SECRET, started, finished, digest=hashlib.sha256))

    def test_cache_entry_written_before_the_fix_does_not_serve_sha1(self):
        secret = self._add_password_secret('SHA256', name='otp-sha256-stale-cache')
        session = self.client.session
        session[f'otp_key_data-{secret.hashid}-{secret.current_revision_id}'] = {
            'otp_key': OTP_SECRET,
            'digits': 6,
        }
        session.save()

        code, started, finished = self._served_code(secret)

        self.assertIn(code, otp_codes_during(OTP_SECRET, started, finished, digest=hashlib.sha256))


@override_settings(**COMMON_OVERRIDES)
class OtpAlgorithmValidationTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.client.force_login(self.owner)
        self.api_client = APIClient()
        self.api_client.force_authenticate(user=self.owner)

    def test_web_form_rejects_an_unknown_algorithm(self):
        response = self.client.post(
            reverse('secrets.secret-add', kwargs={'content_type': 'password'}),
            data={
                'name': 'otp-unknown-algorithm',
                'access_policy': AccessPolicy.DISCOVERABLE.value,
                'password': 'hunter2',
                'otp_key_data': otp_key_data('SHA3'),
            },
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('otp_key_data', response.context['form'].errors)
        self.assertFalse(Secret.objects.filter(name='otp-unknown-algorithm').exists())

    def test_api_rejects_an_unknown_algorithm(self):
        response = self.api_client.post(
            reverse('api.secret_list'),
            {
                'name': 'api-otp-unknown-algorithm',
                'access_policy': 'discoverable',
                'content_type': 'password',
                'secret_data': {'password': 'hunter2', 'otp_key_data': otp_key_data('SHA3')},
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Secret.objects.filter(name='api-otp-unknown-algorithm').exists())
