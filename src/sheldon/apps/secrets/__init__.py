from sys import argv

from django.apps import AppConfig


class SecretsConfig(AppConfig):
    name = 'sheldon.apps.secrets'

    def ready(self):
        if "makemigrations" not in argv and "migrate" not in argv:
            from django.conf import settings
            from .utils import get_secret
            settings.SHELDON_SECRET_KEY = get_secret()
