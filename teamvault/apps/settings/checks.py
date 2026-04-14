from hashlib import sha1
from os import environ

from django.core.checks import Error, Tags, Warning, register


@register(Tags.security)
def check_fernet_key_hash(app_configs, **kwargs):  # noqa: ARG001
    from django.conf import settings
    from django.db.utils import ProgrammingError

    from .models import Setting

    key = getattr(settings, 'TEAMVAULT_SECRET_KEY', '')
    if not key:
        return [
            Error(
                'TEAMVAULT_SECRET_KEY is not configured.',
                hint='Set fernet_key in the [teamvault] section of your config file.',
                id='teamvault.E001',
            )
        ]

    try:
        checksum = Setting.get('fernet_key_hash', default=None)
    except ProgrammingError:
        return [
            Warning(
                'Could not verify fernet_key hash (database not yet migrated).',
                hint='Run migrations first, then check again.',
                id='teamvault.W001',
            )
        ]

    key_hash = sha1(key.encode('utf-8')).hexdigest()

    if checksum is None:
        Setting.set('fernet_key_hash', key_hash)
        return []

    if key_hash != checksum:
        return [
            Error(
                "fernet_key in '{path}' does not match the hash stored in the database ({hash}).".format(
                    hash=checksum,
                    path=environ['TEAMVAULT_CONFIG_FILE'],
                ),
                hint='Ensure you are using the same fernet_key that was used to encrypt existing secrets.',
                id='teamvault.E002',
            )
        ]

    return []
