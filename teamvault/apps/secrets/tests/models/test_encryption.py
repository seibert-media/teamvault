from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model

from cryptography.fernet import Fernet, InvalidToken

from teamvault.apps.secrets.models import Secret, SharedSecretData
from teamvault.apps.secrets.exceptions import PermissionError
from teamvault.apps.secrets.tests.helpers import STATIC_TEST_KEY

User = get_user_model()


@override_settings(TEAMVAULT_SECRET_KEY=STATIC_TEST_KEY)
class SecretEncryptionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="x")
        self.secret = Secret.objects.create(name="enc", created_by=self.user)
        self.secret.set_data(self.user, {"password": "password"}, skip_access_check=True)
        SharedSecretData.objects.create(secret=self.secret, user=self.user, granted_by=self.user)

    def test_round_trip_decrypt_returns_original(self):
        data = self.secret.get_data(self.user)
        self.assertEqual(data["password"], "password")

    def test_ciphertext_not_plaintext(self):
        blob = self.secret.current_revision.encrypted_data
        self.assertIsInstance(blob, (bytes, bytearray))
        self.assertNotIn(b"password", blob)

    def test_wrong_key_raises_invalidtoken(self):
        other_key = Fernet.generate_key()
        with override_settings(TEAMVAULT_SECRET_KEY=other_key):
            with self.assertRaises(InvalidToken):
                self.secret.get_data(self.user)

    def test_missing_key_raises_valueerror(self):
        with override_settings(TEAMVAULT_SECRET_KEY=b""):
            with self.assertRaises(ValueError):
                self.secret.get_data(self.user)
