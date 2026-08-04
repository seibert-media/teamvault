import datetime
import hashlib
import hmac
import secrets as secrets_module
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractUser, Group
from django.db import models
from django.db.models import ExpressionWrapper, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from teamvault.api.v2.scopes import validate_scopes


class User(AbstractUser):
    # TODO: Merge this with UserProfile model
    entry_uuid = models.CharField(max_length=36, default='', blank=True)


class ApiToken(models.Model):
    """Bearer token for API v2: `<prefix>.<secret>`, where only SHA-256(secret) is stored."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='api_tokens')
    name = models.CharField(max_length=200, help_text=_("Human label, e.g. 'CI deploy key'"))
    prefix = models.CharField(max_length=16, db_index=True, unique=True)
    hashed_key = models.CharField(max_length=64)
    scopes = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(blank=True, null=True)
    expires_at = models.DateField()

    MAX_VALIDITY = timedelta(days=365)

    class Meta:
        indexes = [models.Index(fields=['prefix', 'is_active'])]
        constraints = [
            models.CheckConstraint(
                condition=Q(
                    expires_at__lte=ExpressionWrapper(
                        TruncDate('created_at') + timedelta(days=365),
                        output_field=models.DateField(),
                    )
                ),
                name='api_token_expires_within_365d',
            ),
        ]

    def __str__(self):
        return f'{self.name} ({self.prefix})'

    @staticmethod
    def _hash(secret: str) -> str:
        return hashlib.sha256(secret.encode('utf-8')).hexdigest()

    @classmethod
    def issue(
        cls,
        *,
        user,
        name: str,
        scopes: list[str] | None = None,
        expires_at: datetime.date | None = None,
    ) -> tuple['ApiToken', str]:
        """Create a token and return it with the full token string — shown exactly once, never stored."""
        from teamvault.apps.audit.auditlog import log
        from teamvault.apps.audit.models import AuditLogCategoryChoices

        validate_scopes(scopes or [])
        today = timezone.now().date()
        max_expiry = today + cls.MAX_VALIDITY
        if expires_at is None:
            expires_at = max_expiry
        elif expires_at <= today:
            raise ValueError('expires_at must be in the future')
        elif expires_at > max_expiry:
            raise ValueError('expires_at cannot be more than 365 days in the future')

        prefix = secrets_module.token_urlsafe(8)
        secret = secrets_module.token_urlsafe(32)
        token = cls.objects.create(
            user=user,
            name=name,
            prefix=prefix,
            hashed_key=cls._hash(secret),
            scopes=scopes or [],
            expires_at=expires_at,
        )
        log(
            f'API token {name!r} (prefix {prefix}) issued for {user.username}, '
            f'scopes {scopes or []}, expires {expires_at.isoformat()}',
            actor=user,
            category=AuditLogCategoryChoices.API_TOKEN_ISSUED,
            user=user,
        )
        return token, f'{prefix}.{secret}'

    def verify(self, secret: str) -> bool:
        return hmac.compare_digest(self.hashed_key, self._hash(secret))

    def has_scope(self, required: str) -> bool:
        if ':' not in required:
            raise ValueError(f'Scope must be of the form resource:action, got {required!r}')
        resource = required.split(':')[0]
        return any(scope in {required, f'{resource}:*'} for scope in self.scopes)


class UserProfile(models.Model):
    # Since our static files are not served by some webserver but by TeamVault (/Whitenoise) directly
    # to keep the installation overhead low, we'd have to do the same thing with media files.
    # Static files will get replaced with each teamvault deployment, media files should not.
    # Because of that, we'd have to make admins configure a persistent directory for them.
    # For now, that trade-off is not worth it, so let's store avatars as binary data, instead.
    avatar = models.BinaryField(blank=True, null=True)
    default_sharing_groups = models.ManyToManyField(
        Group,
        blank=True,
        help_text=_('New secrets created by you will be shared with these groups.'),
        related_name='+',
    )
    hide_deleted_secrets = models.BooleanField(
        default=True, help_text=_('Hides deleted secrets per default. Enable them in filters to see them again.')
    )
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
