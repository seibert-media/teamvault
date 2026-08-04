from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.accounts.utils import get_pending_secrets_for_user
from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
from teamvault.apps.secrets.models import Secret, SecretRevision, SharedSecretData
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user

User = get_user_model()


def auth_header(token_string):
    return {'HTTP_AUTHORIZATION': f'Bearer {token_string}'}


def _url(user) -> str:
    return f'/api/v2/users/{user.pk}/pending-secrets'


@override_settings(**COMMON_OVERRIDES)
class PendingSecretsTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = make_user('admin', superuser=True)
        cls.target = make_user('target')

        cls.pending = Secret.objects.create(
            name='Critical DB Password',
            created_by=cls.admin,
            access_policy=AccessPolicy.HIDDEN,
            status=SecretStatus.NEEDS_CHANGING,
            needs_changing_on_leave=True,
        )
        SharedSecretData.objects.create(secret=cls.pending, user=cls.target, granted_by=cls.admin)
        rev = SecretRevision.objects.create(
            secret=cls.pending,
            set_by=cls.admin,
            encrypted_data=b'x',
            plaintext_data_sha256='a' * 64,
        )
        rev.accessed_by.add(cls.target)
        cls.pending.current_revision = rev
        cls.pending.save()

        # A secret that is shared+accessed but is OK (not pending) → must be excluded.
        cls.not_pending = Secret.objects.create(
            name='Guest WiFi Password',
            created_by=cls.admin,
            access_policy=AccessPolicy.HIDDEN,
            status=SecretStatus.OK,
            needs_changing_on_leave=True,
        )
        SharedSecretData.objects.create(secret=cls.not_pending, user=cls.target, granted_by=cls.admin)
        ok_rev = SecretRevision.objects.create(
            secret=cls.not_pending,
            set_by=cls.admin,
            encrypted_data=b'y',
            plaintext_data_sha256='b' * 64,
        )
        ok_rev.accessed_by.add(cls.target)
        cls.not_pending.current_revision = ok_rev
        cls.not_pending.save()

        _, cls.admin_token = ApiToken.issue(user=cls.admin, name='admin key', scopes=['users:read'])
        _, cls.nonsuper_token = ApiToken.issue(user=cls.target, name='user key', scopes=['users:read'])

    def _get(self, path, token=None, **params):
        return self.client.get(path, params or None, **auth_header(token or self.admin_token))

    def test_anonymous_request_is_rejected(self):
        response = self.client.get(_url(self.target))
        self.assertEqual(response.status_code, 401)

    def test_requires_users_read_scope(self):
        _, no_scope = ApiToken.issue(user=self.admin, name='no scope', scopes=['secrets:read'])
        response = self._get(_url(self.target), token=no_scope)
        self.assertEqual(response.status_code, 403)

    def test_non_superuser_token_holder_is_forbidden(self):
        response = self._get(_url(self.target), token=self.nonsuper_token)
        self.assertEqual(response.status_code, 403)

    def test_unknown_user_id_returns_404(self):
        response = self._get('/api/v2/users/999999/pending-secrets')
        self.assertEqual(response.status_code, 404)

    def test_returns_only_pending_secrets_with_expected_fields(self):
        response = self._get(_url(self.target))
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body['count'], 1)
        row = body['results'][0]
        self.assertEqual(row['hashid'], self.pending.hashid)
        self.assertEqual(row['name'], 'Critical DB Password')
        self.assertEqual(row['status'], 'needs_changing')
        self.assertIn('http', row['web_url'])
        self.assertIsNotNone(row['last_shared'])
        self.assertIsNotNone(row['last_changed_at'])
        self.assertIn('last_read_at', row)

    def test_parity_with_v1_queryset(self):
        expected = {s.hashid for s in get_pending_secrets_for_user(self.target)}
        response = self._get(_url(self.target))
        returned = {row['hashid'] for row in response.json()['results']}
        self.assertEqual(returned, expected)

    def test_q_filters_by_name(self):
        self.assertEqual(self._get(_url(self.target), q='Critical').json()['count'], 1)
        self.assertEqual(self._get(_url(self.target), q='Banana').json()['count'], 0)

    def test_unknown_query_param_rejected(self):
        response = self._get(_url(self.target), nope='1')
        self.assertEqual(response.status_code, 422)

    def test_error_envelope_is_error_detail(self):
        response = self._get(_url(self.target), token=self.nonsuper_token)
        self.assertEqual(set(response.json().keys()), {'detail'})
