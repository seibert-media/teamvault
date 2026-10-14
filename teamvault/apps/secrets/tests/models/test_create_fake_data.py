from json import loads

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.management import call_command
from django.test import TestCase, override_settings

from teamvault.apps.secrets.fingerprint import payload_fingerprint
from teamvault.apps.secrets.models import SecretRevision
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES


@override_settings(**COMMON_OVERRIDES)
class CreateFakeDataTests(TestCase):
    def test_fake_revisions_carry_the_keyed_fingerprint(self):
        call_command('create_fake_data', verbosity=0)

        fernet = Fernet(settings.TEAMVAULT_SECRET_KEY)
        revisions = list(SecretRevision.objects.all())
        self.assertGreater(len(revisions), 0)
        for revision in revisions:
            payload = loads(fernet.decrypt(bytes(revision.encrypted_data)))
            self.assertEqual(revision.plaintext_data_sha256, payload_fingerprint(revision.secret_id, payload))
