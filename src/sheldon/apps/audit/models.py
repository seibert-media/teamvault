from django.conf import settings
from django.db import models


class LogEntry(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    message = models.TextField()
    password = models.ForeignKey(
        'secrets.Password',
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    password_revision = models.ForeignKey(
        'secrets.PasswordRevision',
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    team = models.ForeignKey(
        'accounts.Team',
        blank=True,
        null=True,
        related_name='logged_actions',
    )
    time = models.DateTimeField(
        auto_now_add=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        blank=True,
        null=True,
        related_name='affected_by_actions',
    )

    class Meta:
        ordering = ('-time',)
