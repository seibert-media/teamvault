from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from teamvault.apps.accounts.models import ApiToken


class Command(BaseCommand):
    help = 'Issue an API v2 bearer token for a user. The token string is printed exactly once.'

    def add_arguments(self, parser):  # noqa: PLR6301
        parser.add_argument('username', help='User the token will act as')
        parser.add_argument('--name', required=True, help="Human label for the token, e.g. 'CI deploy key'")
        parser.add_argument(
            '--scopes',
            default='',
            help="Comma-separated scopes, e.g. 'secrets:read,secrets:data:read' (default: no scopes)",
        )
        parser.add_argument('--days', type=int, default=365, help='Validity in days (max 365, default 365)')

    def handle(self, *args, **options):  # noqa: ARG002
        user_model = get_user_model()
        try:
            user = user_model.objects.get(username=options['username'], is_active=True)
        except user_model.DoesNotExist as exc:
            raise CommandError(f'No active user named {options["username"]!r}') from exc

        scopes = [scope.strip() for scope in options['scopes'].split(',') if scope.strip()]
        expires_at = timezone.now().date() + timedelta(days=options['days'])
        try:
            token, token_string = ApiToken.issue(user=user, name=options['name'], scopes=scopes, expires_at=expires_at)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            f'Token {token.name!r} for {user.username}, scopes {token.scopes}, expires {token.expires_at}'
        )
        self.stdout.write('This token string is shown exactly once and cannot be recovered:')
        self.stdout.write(token_string)
