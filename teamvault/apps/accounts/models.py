import secrets

from django.contrib.auth.models import Group, User
from django.core.validators import MinLengthValidator
from django.db import models
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _


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
        default=True,
        help_text=_('Hides deleted secrets per default. Enable them in filters to see them again.')
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')


class UserToken(models.Model):
    user = models.ForeignKey(
        to=User,
        on_delete=models.CASCADE,
        related_name='tokens'
    )
    created = models.DateTimeField(
        auto_now_add=True
    )
    expires = models.DateTimeField(
        blank=True,
        null=True
    )
    last_used = models.DateTimeField(
        blank=True,
        null=True
    )
    key = models.CharField(
        max_length=40,
        unique=True,
        validators=[MinLengthValidator(40)]
    )
    write_enabled = models.BooleanField(
        default=True,
        help_text=_('Allows Create, Update & Delete operations with this key.')
    )
    label = models.CharField(
        max_length=80,
        blank=True
    )

    class Meta:
        verbose_name = _('token')
        verbose_name_plural = _('tokens')

    def __str__(self):
        return self.key

    @property
    def partial(self):
        return "*" * 36 + self.key[-6:] if self.key else ''

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    @staticmethod
    def generate_key():
        return secrets.token_hex(20)

    @property
    def is_expired(self):
        if self.expires is None or now() < self.expires:
            return False
        return True
