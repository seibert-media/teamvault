from django.conf import settings
from django.db import models


class LogEntry(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        models.PROTECT,
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    group = models.ForeignKey(
        'auth.Group',
        models.PROTECT,
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    message = models.TextField()
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
        ordering = ('-time',)
