from django.conf import settings
from django.db import models
from django.db.models import TextChoices
from django.utils.translation import gettext_lazy as _


class AuditLogCategoryChoices(TextChoices):
    SECRET_READ = 'secret_read', _('secret_read')
    SECRET_ELEVATED_SUPERUSER_READ = 'secret_elevated_superuser_read', _('secret_elevated_superuser_read')
    SECRET_PERMISSION_VIOLATION = 'secret_permission_violation', _('secret_permission_violation')
    SECRET_CHANGED = 'secret_changed', _('secret_changed')
    SECRET_NEEDS_CHANGING_REMINDER = 'secret_needs_changing_reminder', _('secret_needs_changing_reminder')
    SECRET_SHARED = 'secret_shared', _('secret_shared')
    SECRET_SUPERUSER_SHARED = 'secret_superuser_shared', _('secret_superuser_shared')
    SECRET_SHARE_REMOVED = 'secret_share_removed', _('secret_share_removed')
    SECRET_SUPERUSER_SHARE_REMOVED = 'secret_superuser_share_removed', _('secret_superuser_share_removed')
    SECRET_ACCESS_REQUEST = 'secret_legacy_access_requests', _('secret_legacy_access_requests')

    USER_ACTIVATED = 'user_activated', _('user_activated')
    USER_DEACTIVATED = 'user_deactivated', _('user_deactivated')
    USER_SETTINGS_CHANGED = 'user_settings_changed', _('user_settings_changed')

    SHARE_AUTOMATICALLY_REVOKED = 'share_automatically_revoked', _('share_automatically_revoked')

    MISCELLANEOUS = 'miscellaneous', _('miscellaneous')


class LogEntry(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        models.PROTECT,
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    category = models.CharField(
        choices=AuditLogCategoryChoices.choices,
        default=AuditLogCategoryChoices.MISCELLANEOUS,
        max_length=64,
    )
    group = models.ForeignKey(
        'auth.Group',
        models.PROTECT,
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    message = models.TextField()
    reason = models.TextField(
        blank=True,
        null=True,
    )
    secret = models.ForeignKey(
        'secrets.Secret',
        models.PROTECT,
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    secret_revision = models.ForeignKey(
        'secrets.SecretRevision',
        models.PROTECT,
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    time = models.DateTimeField(
        auto_now_add=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        models.PROTECT,
        blank=True,
        null=True,
        related_name='affected_by_actions',
    )

    class Meta:
        indexes = [
            models.Index(fields=['category'], name='logentry_category_idx'),
            models.Index(fields=['time'], name='logentry_time_idx'),
            models.Index(fields=['category', 'time'], name='logentry_category_time_idx'),

            models.Index(fields=['actor'], name='logentry_actor_idx'),
            models.Index(fields=['group'], name='logentry_group_idx'),
            models.Index(fields=['secret'], name='logentry_secret_idx'),
            models.Index(fields=['user'], name='logentry_user_idx'),
        ]
        ordering = ('-time',)
