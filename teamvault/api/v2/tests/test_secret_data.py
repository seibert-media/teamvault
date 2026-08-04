from base64 import b64decode, b64encode

from django.test import TestCase, override_settings

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry
from teamvault.apps.secrets.enums import AccessPolicy, ContentType
from teamvault.apps.secrets.services.revision import RevisionService
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user, new_secret


def auth_header(token_string):
    return {'HTTP_AUTHORIZATION': f'Bearer {token_string}'}


@override_settings(**COMMON_OVERRIDES)
class PayloadReadRoundTripTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        _, cls.token = ApiToken.issue(user=cls.owner, name='data', scopes=['secrets:data:read'])
        cls.password = new_secret(
            cls.owner,
            content_type=ContentType.PASSWORD,
            payload={'password': 's3cr3t'},
            access_policy=AccessPolicy.ANY,
            name='pw',
        )
        cls.cc = new_secret(
            cls.owner,
            content_type=ContentType.CC,
            access_policy=AccessPolicy.ANY,
            name='card',
        )
        cls.file = new_secret(
            cls.owner,
            content_type=ContentType.FILE,
            payload={'file_content': b64encode(b'hello-from-bytes').decode('ascii')},
            access_policy=AccessPolicy.ANY,
            name='file',
        )

    def _get(self, path):
        return self.client.get(path, **auth_header(self.token))

    def test_password_payload_shape(self):
        body = self._get(f'/api/v2/secrets/{self.password.hashid}/data').json()
        self.assertEqual(set(body), {'password', 'otp_key_data'})
        self.assertEqual(body['password'], 's3cr3t')
        self.assertEqual(body['otp_key_data'], '')

    def test_credit_card_payload_shape(self):
        body = self._get(f'/api/v2/secrets/{self.cc.hashid}/data').json()
        self.assertEqual(
            set(body),
            {'holder', 'expiration_month', 'expiration_year', 'number', 'security_code', 'password'},
        )
        self.assertEqual(body['holder'], 'Jane Doe')
        self.assertEqual(body['number'], '4111111111111111')

    def test_file_payload_uses_file_content_not_file(self):
        body = self._get(f'/api/v2/secrets/{self.file.hashid}/data').json()
        self.assertEqual(set(body), {'filename', 'file_content'})
        self.assertNotIn('file', body)
        self.assertEqual(b64decode(body['file_content']), b'hello-from-bytes')
        self.assertEqual(body['filename'], 'hello.bin')


@override_settings(**COMMON_OVERRIDES)
class PayloadReadScopeTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        _, cls.read_token = ApiToken.issue(user=cls.owner, name='read', scopes=['secrets:read'])
        cls.secret = new_secret(cls.owner, access_policy=AccessPolicy.ANY, name='pw')
        cls.revision_hashid = cls.secret.changes.first().hashid

    def _get(self, path):
        return self.client.get(path, **auth_header(self.read_token))

    def test_data_requires_data_read_scope(self):
        self.assertEqual(self._get(f'/api/v2/secrets/{self.secret.hashid}/data').status_code, 403)

    def test_revision_data_requires_data_read_scope(self):
        path = f'/api/v2/secrets/{self.secret.hashid}/revisions/{self.revision_hashid}/data'
        self.assertEqual(self._get(path).status_code, 403)

    def test_otp_requires_data_read_scope(self):
        self.assertEqual(self._get(f'/api/v2/secrets/{self.secret.hashid}/otp').status_code, 403)


@override_settings(**COMMON_OVERRIDES)
class PayloadReadVisibilityTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.viewer = make_user('viewer')
        cls.other = make_user('other')
        _, cls.token = ApiToken.issue(user=cls.viewer, name='data', scopes=['secrets:data:read'])
        cls.hidden = new_secret(cls.other, access_policy=AccessPolicy.HIDDEN, name='Hidden')
        cls.discoverable = new_secret(cls.other, access_policy=AccessPolicy.DISCOVERABLE, name='Discoverable')

    def _get(self, path):
        return self.client.get(path, **auth_header(self.token))

    def test_invisible_secret_returns_404(self):
        self.assertEqual(self._get(f'/api/v2/secrets/{self.hidden.hashid}/data').status_code, 404)

    def test_visible_but_unreadable_returns_403(self):
        self.assertEqual(self._get(f'/api/v2/secrets/{self.discoverable.hashid}/data').status_code, 403)

    def test_unknown_secret_returns_404(self):
        self.assertEqual(self._get('/api/v2/secrets/nope/data').status_code, 404)


@override_settings(**COMMON_OVERRIDES)
class RevisionDataTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        _, cls.token = ApiToken.issue(user=cls.owner, name='data', scopes=['secrets:data:read'])
        cls.secret = new_secret(
            cls.owner,
            payload={'password': 'first'},
            access_policy=AccessPolicy.ANY,
            name='pw',
        )
        cls.first_change = cls.secret.changes.first()
        RevisionService.save_payload(secret=cls.secret, actor=cls.owner, payload={'password': 'second'})
        cls.secret.refresh_from_db()
        cls.other = new_secret(cls.owner, access_policy=AccessPolicy.ANY, name='other')
        cls.other_change = cls.other.changes.first()

    def _get(self, path):
        return self.client.get(path, **auth_header(self.token))

    def test_revision_data_returns_that_revisions_payload(self):
        path = f'/api/v2/secrets/{self.secret.hashid}/revisions/{self.first_change.hashid}/data'
        body = self._get(path).json()
        self.assertEqual(body['password'], 'first')

    def test_revision_of_other_secret_returns_404(self):
        path = f'/api/v2/secrets/{self.secret.hashid}/revisions/{self.other_change.hashid}/data'
        self.assertEqual(self._get(path).status_code, 404)

    def test_unknown_revision_returns_404(self):
        path = f'/api/v2/secrets/{self.secret.hashid}/revisions/nope/data'
        self.assertEqual(self._get(path).status_code, 404)


@override_settings(**COMMON_OVERRIDES)
class PayloadReadAuditTest(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        # A reader distinct from the creator, so they have not yet seen the payload.
        self.reader = make_user('reader')
        _, self.token = ApiToken.issue(user=self.reader, name='data', scopes=['secrets:data:read'])
        self.secret = new_secret(
            self.owner,
            payload={'password': 'pw'},
            access_policy=AccessPolicy.ANY,
            name='pw',
        )

    def _get(self, path):
        return self.client.get(path, **auth_header(self.token))

    def _read_count(self, category):
        return LogEntry.objects.filter(actor=self.reader, secret=self.secret, category=category).count()

    def test_data_read_updates_accessed_by_and_last_read_and_logs(self):
        revision = self.secret.current_revision
        self.assertNotIn(self.reader, revision.accessed_by.all())
        self.assertEqual(self._read_count(AuditLogCategoryChoices.SECRET_READ), 0)

        self.assertEqual(self._get(f'/api/v2/secrets/{self.secret.hashid}/data').status_code, 200)

        revision.refresh_from_db()
        self.secret.refresh_from_db()
        self.assertIn(self.reader, revision.accessed_by.all())
        self.assertIsNotNone(revision.last_read)
        self.assertIsNotNone(self.secret.last_read)
        self.assertEqual(self._read_count(AuditLogCategoryChoices.SECRET_READ), 1)


@override_settings(**COMMON_OVERRIDES)
class SuperuserElevatedReadTest(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.admin = make_user('admin', superuser=True)
        _, self.token = ApiToken.issue(user=self.admin, name='data', scopes=['secrets:data:read'])
        # Hidden secret the admin has no share for; readable only via superuser elevation.
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN, name='hidden-pw')

    def test_superuser_read_logs_elevated_category(self):
        path = f'/api/v2/secrets/{self.secret.hashid}/data'
        self.assertEqual(self.client.get(path, **auth_header(self.token)).status_code, 200)
        self.assertEqual(
            LogEntry.objects.filter(
                actor=self.admin,
                secret=self.secret,
                category=AuditLogCategoryChoices.SECRET_ELEVATED_SUPERUSER_READ,
            ).count(),
            1,
        )


@override_settings(**COMMON_OVERRIDES)
class OtpReadTest(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        _, self.token = ApiToken.issue(user=self.owner, name='data', scopes=['secrets:data:read'])
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.ANY, name='otp')
        RevisionService.save_payload(
            secret=self.secret,
            actor=self.owner,
            payload={'otp_key': 'JBSWY3DPEHPK3PXP', 'digits': '6', 'algorithm': 'SHA1'},
        )
        self.secret.refresh_from_db()

    def _get(self):
        return self.client.get(f'/api/v2/secrets/{self.secret.hashid}/otp', **auth_header(self.token))

    def _read_count(self):
        return LogEntry.objects.filter(
            actor=self.owner,
            secret=self.secret,
            secret_revision=self.secret.current_revision,
            category=AuditLogCategoryChoices.SECRET_READ,
        ).count()

    def test_otp_returns_token(self):
        response = self._get()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['otp'].isdigit())

    def test_repeated_otp_refresh_logs_secret_read_once(self):
        self.assertEqual(self._read_count(), 0)
        first = self._get()
        self.assertEqual(first.status_code, 200)
        self.assertEqual(self._read_count(), 1)
        second = self._get()
        self.assertEqual(second.status_code, 200)
        self.assertEqual(self._read_count(), 1)

    def test_otp_without_otp_key_returns_422(self):
        plain = new_secret(self.owner, payload={'password': 'pw'}, access_policy=AccessPolicy.ANY, name='plain')
        response = self.client.get(f'/api/v2/secrets/{plain.hashid}/otp', **auth_header(self.token))
        self.assertEqual(response.status_code, 422)


@override_settings(**COMMON_OVERRIDES)
class PayloadReadV1ParityTest(TestCase):
    """Payloads created via the v1 DRF create path round-trip through the v2 read endpoints."""

    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        _, cls.token = ApiToken.issue(user=cls.owner, name='data', scopes=['secrets:data:read'])

    def _create_via_v1(self, content_type, secret_data):
        from teamvault.apps.secrets.api.serializers import SecretSerializer

        class _Req:
            user = self.owner

        ser = SecretSerializer(
            data={'name': 'x', 'access_policy': 'any', 'content_type': content_type, 'secret_data': secret_data},
            context={'request': _Req()},
        )
        self.assertTrue(ser.is_valid(), ser.errors)
        instance = ser.save(created_by=self.owner)
        RevisionService.save_payload(secret=instance, actor=self.owner, payload=instance._data, skip_acl=True)
        instance.refresh_from_db()
        return instance

    def test_v1_created_password_roundtrips(self):
        secret = self._create_via_v1('password', {'password': 'v1pw'})
        body = self.client.get(f'/api/v2/secrets/{secret.hashid}/data', **auth_header(self.token)).json()
        self.assertEqual(body['password'], 'v1pw')
