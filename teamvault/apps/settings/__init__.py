from sys import argv

from django.apps import AppConfig


class SettingsConfig(AppConfig):
    name = 'teamvault.apps.settings'

    def ready(self):
        if "makemigrations" in argv or "migrate" in argv or "upgrade" in argv:
            return

        from django.conf import settings
        from . import config
        parsed_config = config.get_config()
        config.configure_base_url(parsed_config, settings)
        config.configure_debugging(parsed_config, settings)
        config.configure_ldap_auth(parsed_config, settings)
        config.configure_max_file_size(parsed_config, settings)
        config.configure_teamvault_secret_key(parsed_config, settings)
