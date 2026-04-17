import json

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import override_settings
from django_test_migrations.contrib.unittest_case import MigratorTestCase

from teamvault.apps.secrets.models import Secret, SecretRevision

User = get_user_model()

STATIC_TEST_KEY = b'WKGGUS52yN68AtcgOKKKqDzccS3hOy32ShZWKwDWe3Q='


def _encrypt(key: bytes, plaintext: str) -> bytes:
    return Fernet(key).encrypt(plaintext.encode('utf-8'))


def _decrypt_as_json(key: bytes, encrypted):
    return json.loads(Fernet(key).decrypt(bytes(encrypted)).decode('utf-8'))


@override_settings(TEAMVAULT_SECRET_KEY=STATIC_TEST_KEY)
class Secret0041MigrationTest(MigratorTestCase):
    """
    Ensure password payload migration works for the expected legacy formats.
    After migration, all PASSWORD-type SecretRevisions should have their
    encrypted payloads stored as JSON dicts with a 'password' key.
    """

    apps = ['accounts', 'audit', 'settings']
    migrate_from = ('secrets', '0040_secretchange_scrubbed_fields')
    migrate_to = ('secrets', '0041_fix_passwords_old_payload')

    def prepare(self):
        user = User.objects.create_user(username='pwd migration test user')
        user.save()
        call_command('migrate', 'settings', verbosity=0)
        call_command('migrate', 'social_django', verbosity=0)
        call_command('migrate', 'secrets', '0040', verbosity=0)

        secret = Secret.objects.create(
            name='Legacy Password Secret',
            created_by=user,
            content_type=1,  # ContentType.PASSWORD
            access_policy=1,  # AccessPolicy.DISCOVERABLE
            status=1,  # SecretStatus.OK
        )

        # Old format: password stored as a JSON-encoded string, not a dict.
        SecretRevision.objects.create(
            secret=secret,
            encrypted_data=_encrypt(STATIC_TEST_KEY, '"my-old-password"'),
            otp_key_set=False,
            length=0,
            plaintext_data_sha256='sha256-json-string',
            set_by=user,
        )

        # New format: already stored as a JSON dict — should be left untouched.
        SecretRevision.objects.create(
            secret=secret,
            encrypted_data=_encrypt(STATIC_TEST_KEY, '{"password": "already-new"}'),
            otp_key_set=False,
            length=0,
            plaintext_data_sha256='sha256-already-dict',
            set_by=user,
        )

        # Password + OTP dict — all keys must survive intact.
        SecretRevision.objects.create(
            secret=secret,
            encrypted_data=_encrypt(STATIC_TEST_KEY, '{"password": "pw", "otp_key": "JBSWY3DPEHPK3PXP", "digits": 6}'),
            otp_key_set=True,
            length=0,
            plaintext_data_sha256='sha256-otp-dict',
            set_by=user,
        )

        cc_secret = Secret.objects.create(
            name='Legacy CC Secret',
            created_by=user,
            content_type=2,  # ContentType.CC
            access_policy=1,
            status=1,
        )

        # CC revision — must not be touched because the filter targets content_type=1 only.
        SecretRevision.objects.create(
            secret=cc_secret,
            encrypted_data=_encrypt(STATIC_TEST_KEY, '{"holder": "John Doe", "number": "4111111111111111"}'),
            otp_key_set=False,
            length=0,
            plaintext_data_sha256='sha256-cc',
            set_by=user,
        )

        call_command('migrate', 'secrets', '0041', verbosity=0)

    def _revision_by_sha(self, sha_suffix: str):
        return self.new_state.apps.get_model('secrets', 'SecretRevision').objects.get(
            plaintext_data_sha256=f'sha256-{sha_suffix}'
        )

    def test_json_string_payload_migrated_to_dict(self):
        """Old format: JSON-encoded string → should become {"password": <value>}."""
        revision = self._revision_by_sha('json-string')
        self.assertEqual(_decrypt_as_json(STATIC_TEST_KEY, revision.encrypted_data), {'password': 'my-old-password'})

    def test_already_dict_payload_unchanged(self):
        """New format: already a JSON dict → should remain untouched."""
        revision = self._revision_by_sha('already-dict')
        self.assertEqual(_decrypt_as_json(STATIC_TEST_KEY, revision.encrypted_data), {'password': 'already-new'})

    def test_otp_dict_payload_unchanged(self):
        """Password+OTP dict → all keys must survive intact."""
        revision = self._revision_by_sha('otp-dict')
        self.assertEqual(
            _decrypt_as_json(STATIC_TEST_KEY, revision.encrypted_data),
            {'password': 'pw', 'otp_key': 'JBSWY3DPEHPK3PXP', 'digits': 6},
        )

    def test_cc_revision_not_processed(self):
        """CC revisions must not be touched — the migration filter targets content_type=1 only."""
        SecretRevisionModel = self.new_state.apps.get_model('secrets', 'SecretRevision')
        revision = SecretRevisionModel.objects.get(plaintext_data_sha256='sha256-cc')
        self.assertEqual(
            _decrypt_as_json(STATIC_TEST_KEY, revision.encrypted_data),
            {'holder': 'John Doe', 'number': '4111111111111111'},
        )


@override_settings(TEAMVAULT_SECRET_KEY=STATIC_TEST_KEY)
class Secret0041RawStringMigrationTest(MigratorTestCase):
    """
    Ensure the migration also handles very old passwords stored as raw plaintext
    (not valid JSON) — the pre-JSON-era format that Secret.get_data() still
    guards against with its own JSONDecodeError fallback.
    """

    apps = ['accounts', 'audit', 'settings']
    migrate_from = ('secrets', '0040_secretchange_scrubbed_fields')
    migrate_to = ('secrets', '0041_fix_passwords_old_payload')

    def prepare(self):
        user = User.objects.create_user(username='pwd raw string test user')
        user.save()
        call_command('migrate', 'settings', verbosity=0)
        call_command('migrate', 'social_django', verbosity=0)
        call_command('migrate', 'secrets', '0040', verbosity=0)

        secret = Secret.objects.create(
            name='Very Old Password Secret',
            created_by=user,
            content_type=1,  # ContentType.PASSWORD
            access_policy=1,  # AccessPolicy.DISCOVERABLE
            status=1,  # SecretStatus.OK
        )

        # Very old format: raw plaintext string, not valid JSON at all.
        SecretRevision.objects.create(
            secret=secret,
            encrypted_data=_encrypt(STATIC_TEST_KEY, 'my-raw-password'),
            otp_key_set=False,
            length=0,
            plaintext_data_sha256='sha256-raw-string',
            set_by=user,
        )

        call_command('migrate', 'secrets', '0041', verbosity=0)

    def test_raw_string_payload_migrated_to_dict(self):
        """Very old format: raw non-JSON string → should become {"password": <value>}."""
        revision = self.new_state.apps.get_model('secrets', 'SecretRevision').objects.get(
            plaintext_data_sha256='sha256-raw-string'
        )
        self.assertEqual(_decrypt_as_json(STATIC_TEST_KEY, revision.encrypted_data), {'password': 'my-raw-password'})
