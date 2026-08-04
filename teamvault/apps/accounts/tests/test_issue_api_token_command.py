from datetime import timedelta
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.test import TestCase
from django.utils import timezone

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry

User = get_user_model()


class IssueApiTokenCommandTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='alice', password='pw')

    @staticmethod
    def issue(*args):
        out = StringIO()
        call_command('issue_api_token', *args, stdout=out)
        return out.getvalue()

    def test_issues_working_token_and_prints_it_once(self):
        output = self.issue('alice', '--name', 'CI key', '--scopes', 'secrets:read,secrets:data:read')
        token = ApiToken.objects.get(user=self.user)
        self.assertEqual(token.name, 'CI key')
        self.assertEqual(token.scopes, ['secrets:read', 'secrets:data:read'])
        token_string = next(line for line in output.splitlines() if line.startswith(token.prefix))
        self.assertTrue(token.verify(token_string.split('.', 1)[1]))

    def test_days_option_sets_expiry(self):
        self.issue('alice', '--name', 'key', '--days', '30')
        token = ApiToken.objects.get(user=self.user)
        self.assertEqual(token.expires_at, timezone.now().date() + timedelta(days=30))

    def test_rejects_unknown_user(self):
        with self.assertRaises(CommandError):
            self.issue('nobody', '--name', 'key')

    def test_rejects_invalid_scope(self):
        with self.assertRaises(CommandError):
            self.issue('alice', '--name', 'key', '--scopes', 'secrets:admin')

    def test_writes_audit_log_entry(self):
        self.issue('alice', '--name', 'CI key')
        entry = LogEntry.objects.filter(category=AuditLogCategoryChoices.API_TOKEN_ISSUED).latest('time')
        self.assertEqual(entry.user, self.user)
