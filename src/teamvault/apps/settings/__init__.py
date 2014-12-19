from sys import argv

from django.apps import AppConfig


class SettingsConfig(AppConfig):
    name = 'teamvault.apps.settings'

    def ready(self):
        if "makemigrations" in argv or "migrate" in argv:
            return

        from django.conf import settings
        from . import config

        config.configure_base_url(config.CONFIG, settings)
        config.configure_ldap_auth(config.CONFIG, settings)
        config.configure_teamvault_secret_key(config.CONFIG, settings)
