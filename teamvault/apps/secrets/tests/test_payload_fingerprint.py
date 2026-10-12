from hashlib import sha256
from json import dumps

from cryptography.fernet import Fernet
from django.test import SimpleTestCase, override_settings

from teamvault.apps.secrets.fingerprint import payload_fingerprint

KEY_A = Fernet.generate_key()
KEY_B = Fernet.generate_key()
PAYLOAD = {'password': 'hunter2', 'otp_key': 'JBSWY3DPEHPK3PXP'}


@override_settings(TEAMVAULT_SECRET_KEY=KEY_A)
class PayloadFingerprintTest(SimpleTestCase):
    def test_is_deterministic_hex_digest(self):
        first = payload_fingerprint(1, PAYLOAD)
        second = payload_fingerprint(1, PAYLOAD)
        self.assertEqual(first, second)
        self.assertRegex(first, r'^[0-9a-f]{64}$')

    def test_ignores_payload_key_order(self):
        reordered = {'otp_key': PAYLOAD['otp_key'], 'password': PAYLOAD['password']}
        self.assertEqual(payload_fingerprint(1, PAYLOAD), payload_fingerprint(1, reordered))

    def test_differs_between_secrets(self):
        self.assertNotEqual(payload_fingerprint(1, PAYLOAD), payload_fingerprint(2, PAYLOAD))

    def test_differs_between_keys(self):
        with_key_a = payload_fingerprint(1, PAYLOAD)
        with override_settings(TEAMVAULT_SECRET_KEY=KEY_B):
            with_key_b = payload_fingerprint(1, PAYLOAD)
        self.assertNotEqual(with_key_a, with_key_b)

    def test_is_not_the_plain_sha256_of_the_payload(self):
        plain = sha256(dumps(PAYLOAD, sort_keys=True).encode()).hexdigest()
        self.assertNotEqual(payload_fingerprint(1, PAYLOAD), plain)

    def test_accepts_string_key_setting(self):
        with override_settings(TEAMVAULT_SECRET_KEY=KEY_A.decode()):
            as_str = payload_fingerprint(1, PAYLOAD)
        self.assertEqual(as_str, payload_fingerprint(1, PAYLOAD))
