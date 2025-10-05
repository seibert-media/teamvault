from django.test import TestCase, override_settings
from cryptography.fernet import Fernet, InvalidToken

from teamvault.apps.secrets.models import Secret
from teamvault.apps.secrets.services.revision import RevisionService
from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class SecretEncryptionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = make_user("alice")
        cls.secret: Secret = new_secret(cls.user, name="enc")
        RevisionService.save_payload(
            secret=cls.secret,
            actor=cls.user,
            payload={"password": "password"},
        )

    def test_round_trip_decrypt_returns_original(self):
        data = self.secret.get_data(self.user)
        self.assertEqual(data["password"], "password")

    def test_ciphertext_does_not_contain_plaintext(self):
        plaintext = self.secret.get_data(self.user)["password"].encode("utf-8")
        blob = self.secret.current_revision.encrypted_data
        self.assertIsInstance(blob, (bytes, bytearray))
        self.assertNotIn(plaintext, blob)

    def test_wrong_key_raises_invalidtoken(self):
        other_key = Fernet.generate_key()
        with override_settings(TEAMVAULT_SECRET_KEY=other_key):
            with self.assertRaises(InvalidToken):
                self.secret.get_data(self.user)

    def test_missing_key_raises_valueerror(self):
        with override_settings(TEAMVAULT_SECRET_KEY=b""):
            with self.assertRaises(ValueError):
                self.secret.get_data(self.user)
