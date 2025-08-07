from base64 import b64encode, b64decode
from json import loads

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import override_settings
from django_test_migrations.contrib.unittest_case import MigratorTestCase

from teamvault.apps.secrets.models import Secret

STATIC_TEST_KEY = b"WKGGUS52yN68AtcgOKKKqDzccS3hOy32ShZWKwDWe3Q="


@override_settings(TEAMVAULT_SECRET_KEY=STATIC_TEST_KEY)
class Secret0038MigrationTest(MigratorTestCase):
    """
        Ensure file migration works as expected.
        After migration we want all files to be safed as encrypted dict,
        where the content is b64 encoded
    """
    apps = ['accounts', 'audit', 'settings']
    migrate_from = ('secrets', '0037_change_secretrevision_plaintextdata_key_of_password_type')
    migrate_to = ('secrets', '0038_migrate_old_file_saves_into_new_format')

    def prepare(self):
        self.fernet_key = Fernet(settings.TEAMVAULT_SECRET_KEY)
        user = User.objects.create_user(username='file migration test user')
        user.save()
        call_command('migrate', 'settings', verbosity=0)
        call_command('migrate', 'social_django', verbosity=0)
        call_command('migrate', 'secrets', '0037', verbosity=0)
        call_command('loaddata', 'test_file_v3_migration_fixtures.json', verbosity=0)
        call_command('migrate', 'secrets', '0038', verbosity=0)

    def test_migration_secrets0038(self):
        HistoricalSecretRevisionModel = self.new_state.apps.get_model('secrets', 'SecretRevision')
        revisions = HistoricalSecretRevisionModel.objects.filter(secret__content_type=Secret.CONTENT_FILE)
        for revision in revisions:
            self.assertTrue(self.check_if_file_secret_is_v3(revision))

    def check_if_file_secret_is_v3(self, revision):
        try:
            decrypted_data = loads(self.fernet_key.decrypt(revision.encrypted_data))
            decrypted_data = decrypted_data['file_content'].encode()
            return b64encode(b64decode(decrypted_data, validate=True)) == decrypted_data
        except Exception as e:
            print(f'Error checking file secret v3 format: {e}')
            return False
