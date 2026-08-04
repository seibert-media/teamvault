import logging
from typing import NoReturn

from django.http import HttpRequest
from django.utils import timezone
from ninja.errors import HttpError
from ninja.security import HttpBearer

from teamvault.apps.accounts.models import ApiToken

logger = logging.getLogger(__name__)


class BearerAuth(HttpBearer):
    def authenticate(self, request: HttpRequest, token_string: str) -> ApiToken:  # noqa: ARG002, PLR6301
        prefix = None

        def _deny(reason: str) -> NoReturn:
            logger.info('api_v2_auth_deny reason=%s prefix=%s', reason, prefix or '?')
            raise HttpError(401, 'Unauthorized')

        try:
            prefix, secret = token_string.split('.', 1)
        except ValueError:
            _deny('malformed')

        try:
            token = ApiToken.objects.select_related('user').get(prefix=prefix, is_active=True)
        except ApiToken.DoesNotExist:
            _deny('not_found_or_inactive')

        if timezone.now().date() > token.expires_at:
            _deny('expired')

        if not token.verify(secret):
            _deny('wrong_secret')

        if not token.user.is_active:
            _deny('user_inactive')

        ApiToken.objects.filter(pk=token.pk).update(last_used_at=timezone.now())
        return token
