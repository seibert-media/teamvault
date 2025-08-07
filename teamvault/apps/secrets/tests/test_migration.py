from django_test_migrations.contrib.unittest_case import MigratorTestCase
from django.core.management import call_command
from django.conf import settings
from django.contrib.auth.models import User

from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from json import loads

from teamvault.apps.secrets.models import Secret


class Secret0038MigrationTest(MigratorTestCase):
    """
        Ensure file migration works as expected.
        After migration we want all files to be safed as encrypted dict,
        where the content is b64 encoded
    """
    apps = ['accounts', 'audit', 'settings']
    migrate_from = ('secrets', '0037_change_secretrevision_plaintextdata_key_of_password_type')
    migrate_to = ('secrets', '0038_migrate_old_file_saves_into_new_format')
    f = Fernet(settings.TEAMVAULT_SECRET_KEY)

    def prepare(self):
        user = User.objects.create_user(username='file migration test user')
        user.save()
        call_command('migrate', 'settings', verbosity=0)
        call_command('migrate', 'social_django', verbosity=0)
        call_command('migrate', 'secrets', '0037', verbosity=0)
        call_command('loaddata', 'test_file_v3_migration_fixtures.json', verbosity=0)
        call_command('migrate', 'secrets', '0038', verbosity=0)

    def test_migration_secrets0038(self):
        HistoricalSecretModel = self.new_state.apps.get_model('secrets', 'Secret')
        file_secrets = HistoricalSecretModel.objects.filter(content_type=Secret.CONTENT_FILE)
        for secret in file_secrets:
            self.assertTrue(self.check_if_file_secret_is_v3(secret))

    def check_if_file_secret_is_v3(self, secret):
        try:
            decrypted_data = loads(self.f.decrypt(secret.current_revision.encrypted_data))
            decrypted_data = decrypted_data['file_content'].encode()
            return b64encode(b64decode(decrypted_data, validate=True)) == decrypted_data
        except Exception:
            return False
