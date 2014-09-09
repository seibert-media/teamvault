try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import SafeConfigParser
from hashlib import sha1
from os import environ
from random import choice
from string import ascii_letters, digits, punctuation

from django.utils.translation import ugettext as _

from ..settings.models import Setting


def generate_password(length=12, alphanum=False):
    """
    Returns a password of the given length.
    """
    char_pool = ascii_letters + digits
    if not alphanum:
        char_pool += punctuation
    return "".join(choice(char_pool) for i in range(length))


def get_secret():
    checksum = Setting.get("fernet_key_hash", default=None)
    config = SafeConfigParser()
    config.read(environ['TEAMVAULT_CONFIG_FILE'])
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
