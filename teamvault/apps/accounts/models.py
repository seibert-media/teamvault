from django.contrib.auth.models import Group, User
from django.db import models
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
