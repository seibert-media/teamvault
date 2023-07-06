from django.contrib.auth.models import User, Group
from django.db import models
from django.utils.translation import gettext_lazy as _


class UserSettings(models.Model):
    default_sharing_groups = models.ManyToManyField(
        Group,
        blank=True,
        help_text=_('New secrets created by you will be shared with these groups.'),
        related_name='+',
    )
    hide_deleted_secrets = models.BooleanField(default=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
