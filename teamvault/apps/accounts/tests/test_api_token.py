import hashlib
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry

User = get_user_model()


class ApiTokenIssueTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='alice', password='pw')

    def test_issue_returns_token_and_prefixed_secret(self):
        token, token_string = ApiToken.issue(user=self.user, name='CI key', scopes=['secrets:read'])
        prefix, secret = token_string.split('.', 1)
        self.assertEqual(token.prefix, prefix)
        self.assertEqual(token.name, 'CI key')
        self.assertEqual(token.scopes, ['secrets:read'])
        self.assertTrue(token.is_active)

    def test_secret_is_stored_only_as_sha256(self):
        token, token_string = ApiToken.issue(user=self.user, name='key', scopes=[])
        secret = token_string.split('.', 1)[1]
        self.assertEqual(token.hashed_key, hashlib.sha256(secret.encode()).hexdigest())
        self.assertNotIn(secret, [token.hashed_key, token.prefix, token.name])

    def test_issue_rejects_invalid_scopes(self):
        with self.assertRaises(ValueError):
            ApiToken.issue(user=self.user, name='key', scopes=['secrets:admin'])

    def test_issue_defaults_to_max_expiry_365_days(self):
        token, _ = ApiToken.issue(user=self.user, name='key', scopes=[])
        self.assertEqual(token.expires_at, timezone.now().date() + timedelta(days=365))

    def test_issue_rejects_expiry_beyond_365_days(self):
        with self.assertRaises(ValueError):
            ApiToken.issue(
                user=self.user, name='key', scopes=[], expires_at=timezone.now().date() + timedelta(days=366)
            )

    def test_issue_rejects_expiry_in_the_past(self):
        with self.assertRaises(ValueError):
            ApiToken.issue(user=self.user, name='key', scopes=[], expires_at=timezone.now().date())

    def test_db_constraint_rejects_expiry_beyond_365_days(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            ApiToken.objects.create(
                user=self.user,
                name='key',
                prefix='abcdef',
                hashed_key='0' * 64,
                expires_at=timezone.now().date() + timedelta(days=400),
            )

    def test_issue_writes_audit_log_entry(self):
        ApiToken.issue(user=self.user, name='CI key', scopes=['secrets:read'])
        entry = LogEntry.objects.filter(category=AuditLogCategoryChoices.API_TOKEN_ISSUED).latest('time')
        self.assertEqual(entry.actor, self.user)
        self.assertIn('CI key', entry.message)


class ApiTokenVerifyTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='alice', password='pw')
        cls.token, cls.token_string = ApiToken.issue(user=cls.user, name='key', scopes=['secrets:read'])

    def test_verify_accepts_correct_secret(self):
        secret = self.token_string.split('.', 1)[1]
        self.assertTrue(self.token.verify(secret))

    def test_verify_rejects_wrong_secret(self):
        self.assertFalse(self.token.verify('wrong-secret'))

    def test_has_scope_exact_match(self):
        self.assertTrue(self.token.has_scope('secrets:read'))
        self.assertFalse(self.token.has_scope('secrets:write'))

    def test_has_scope_does_not_imply_data_read(self):
        self.assertFalse(self.token.has_scope('secrets:data:read'))

    def test_has_scope_wildcard_matches_resource(self):
        token, _ = ApiToken.issue(user=self.user, name='wild', scopes=['secrets:*'])
        self.assertTrue(token.has_scope('secrets:read'))
        self.assertTrue(token.has_scope('secrets:data:read'))
        self.assertTrue(token.has_scope('secrets:write'))
        self.assertFalse(token.has_scope('shares:write'))
