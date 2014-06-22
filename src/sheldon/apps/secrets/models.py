from django.db import models
from django.utils.timezone import now

from .utils import decrypt, encrypt, generate_password


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
        return decrypt(self.encrypted_password)

    def set_password(self, user, new_password):
        self.encrypted_password = encrypt(new_password)
