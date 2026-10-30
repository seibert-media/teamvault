from cryptography.fernet import Fernet
from django.core.management import call_command
from django.test import TestCase, override_settings

from teamvault.apps.secrets.fingerprint import payload_fingerprint
from teamvault.apps.secrets.models import SecretRevision
from teamvault.apps.secrets.services.revision import RevisionService
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, TEST_KEY, make_user, new_secret

NEW_KEY = Fernet.generate_key().decode()


@override_settings(**COMMON_OVERRIDES)
class RotateFernetKeyTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.payload = {'password': 'hunter2'}
        self.secret = new_secret(self.owner, payload=self.payload)

    def test_re_encrypts_and_rehashes_so_dedup_survives_rotation(self):
        with override_settings(TEAMVAULT_SECRET_KEY=NEW_KEY):
            call_command('rotate_fernet_key', '--', TEST_KEY.decode(), verbosity=0)

            revision = SecretRevision.objects.get(secret=self.secret)
            self.assertEqual(revision.get_data(self.owner), self.payload)
            self.assertEqual(revision.plaintext_data_sha256, payload_fingerprint(self.secret.id, self.payload))

            self.secret.refresh_from_db()
            RevisionService.save_payload(secret=self.secret, actor=self.owner, payload=dict(self.payload))
            self.assertEqual(SecretRevision.objects.filter(secret=self.secret).count(), 1)
