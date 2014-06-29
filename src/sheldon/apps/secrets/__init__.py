from django.apps import AppConfig


class SecretsConfig(AppConfig):
    name = 'sheldon.apps.secrets'

    def ready(self):
        from django.conf import settings
        from .utils import get_secret
        settings.SHELDON_SECRET_KEY = get_secret()
