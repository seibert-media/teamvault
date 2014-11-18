
from hashlib import sha1
from os import environ

from django.utils.translation import ugettext as _

from .models import Setting


def get_secret(config):
    checksum = Setting.get("fernet_key_hash", default=None)
    key = config.get("teamvault", "fernet_key")
    key_hash = sha1(key.encode('utf-8')).hexdigest()

    if checksum is None:
        Setting.set("fernet_key_hash", key_hash)

    elif key_hash != checksum:
        raise RuntimeError(_(
            "secret in '{path}' does not match SHA1 hash in database ({hash})"
        ).format(
            hash=checksum,
            path=environ['TEAMVAULT_CONFIG_FILE'],
        ))

    return key
