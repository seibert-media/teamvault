from importlib import metadata

from django.conf import settings


def version(_request):
    return {'version': metadata.version('teamvault')}


def secrets_config(_request):
    return {'enabled_secret_types': settings.TEAMVAULT_ENABLED_SECRET_TYPES}
