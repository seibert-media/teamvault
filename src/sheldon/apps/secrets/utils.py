from hashlib import sha1
from os import umask
from os.path import abspath, exists
from random import choice
from string import digits, letters, punctuation

from cryptography.fernet import Fernet
from django.conf import settings
from django.utils.translation import ugettext as _

from ..settings.models import Setting


def generate_password(length=12, alphanum=False):
    """
    Returns a password of the given length.
    """
    char_pool = letters + digits
    if not alphanum:
        char_pool += punctuation
    return "".join(choice(char_pool) for i in range(length))


def get_secret():
    checksum = Setting.get("secret_hash", default=None)

    if not exists(settings.SHELDON_SECRET_FILE):
        if checksum is not None:
            raise RuntimeError(_("secrets file not found at '{}'").format(
                settings.SHELDON_SECRET_FILE,
            ))
        else:
            key = Fernet.generate_key()
            old_umask = umask(7)
            try:
                with open(settings.SHELDON_SECRET_FILE, 'w') as f:
                    f.write(key)
            finally:
                umask(old_umask)
            Setting.set("secret_hash", sha1(key).hexdigest())
            return key

    with open(settings.SHELDON_SECRET_FILE) as f:
        key = f.read()

    if sha1(key).hexdigest() != checksum:
        raise RuntimeError(_(
            "secret in '{path}' does not match SHA1 hash in database ({hash})"
        ).format(
            hash=checksum,
            path=abspath(settings.SHELDON_SECRET_FILE),
        ))
    return key
