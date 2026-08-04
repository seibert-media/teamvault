from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from teamvault.apps.accounts.models import ApiToken

User = get_user_model()


def auth_header(token_string):
    return {'HTTP_AUTHORIZATION': f'Bearer {token_string}'}


class MeAuthenticationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='alice', password='pw', first_name='Alice', last_name='Doe')
        cls.token, cls.token_string = ApiToken.issue(user=cls.user, name='CI key', scopes=['secrets:read'])

    def test_anonymous_request_is_rejected(self):
        response = self.client.get('/api/v2/me')
        self.assertEqual(response.status_code, 401)

    def test_malformed_token_is_rejected(self):
        response = self.client.get('/api/v2/me', **auth_header('no-dot-in-here'))
        self.assertEqual(response.status_code, 401)

    def test_unknown_prefix_is_rejected(self):
        response = self.client.get('/api/v2/me', **auth_header('unknown.secret'))
        self.assertEqual(response.status_code, 401)

    def test_wrong_secret_is_rejected(self):
        response = self.client.get('/api/v2/me', **auth_header(f'{self.token.prefix}.wrong'))
        self.assertEqual(response.status_code, 401)

    def test_revoked_token_is_rejected(self):
        ApiToken.objects.filter(pk=self.token.pk).update(is_active=False)
        response = self.client.get('/api/v2/me', **auth_header(self.token_string))
        self.assertEqual(response.status_code, 401)

    def test_expired_token_is_rejected(self):
        ApiToken.objects.filter(pk=self.token.pk).update(expires_at=timezone.now().date() - timedelta(days=1))
        response = self.client.get('/api/v2/me', **auth_header(self.token_string))
        self.assertEqual(response.status_code, 401)

    def test_token_of_inactive_user_is_rejected(self):
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        response = self.client.get('/api/v2/me', **auth_header(self.token_string))
        self.assertEqual(response.status_code, 401)

    def test_error_envelope_is_error_detail(self):
        response = self.client.get('/api/v2/me')
        self.assertEqual(set(response.json().keys()), {'detail'})


class MeResponseTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='alice', password='pw', first_name='Alice', last_name='Doe')
        cls.token, cls.token_string = ApiToken.issue(user=cls.user, name='CI key', scopes=['secrets:read'])

    def test_me_returns_token_and_user(self):
        response = self.client.get('/api/v2/me', **auth_header(self.token_string))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(
            body['user'],
            {'id': self.user.pk, 'username': 'alice', 'full_name': 'Alice Doe'},
        )
        self.assertEqual(body['token']['name'], 'CI key')
        self.assertEqual(body['token']['prefix'], self.token.prefix)
        self.assertEqual(body['token']['scopes'], ['secrets:read'])
        self.assertEqual(body['token']['expires_at'], self.token.expires_at.isoformat())

    def test_successful_request_updates_last_used_at(self):
        self.assertIsNone(self.token.last_used_at)
        self.client.get('/api/v2/me', **auth_header(self.token_string))
        self.token.refresh_from_db()
        self.assertIsNotNone(self.token.last_used_at)
