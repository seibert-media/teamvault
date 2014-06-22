from cryptography.fernet import Fernet
from django.conf import settings
from django.db import models
from django.utils.timezone import now

from .utils import generate_password


def _generate_id_token():
    return generate_password(length=32, alphanum=True)


class Secret(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(default=now)
    name = models.CharField(max_length=92)
    id_token = models.CharField(
        default=_generate_id_token,
        max_length=32,
        unique=True,
    )
    class Meta:
        abstract = True


class Password(Secret):
    encrypted_password = models.TextField()

    def get_password(self, user):
        f = Fernet(settings.SHELDON_SECRET_KEY)
        return f.decrypt(self.encrypted_password)

    def set_password(self, user, new_password):
        f = Fernet(settings.SHELDON_SECRET_KEY)
        self.encrypted_password = f.encrypt(new_password)
