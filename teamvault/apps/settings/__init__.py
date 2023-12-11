from django.apps import AppConfig


class SettingsConfig(AppConfig):
    name = 'teamvault.apps.settings'

    def ready(self):
        from django.conf import settings
        from . import config, webpack
        parsed_config = config.get_config()
        config.configure_base_url(parsed_config, settings)
        config.configure_debugging(parsed_config, settings)
        config.configure_ldap_auth(parsed_config, settings)
        config.configure_google_auth(parsed_config, settings)
        config.configure_max_file_size(parsed_config, settings)
        config.configure_password_generator(parsed_config, settings)
        config.configure_superuser_reads(parsed_config, settings)
        config.configure_teamvault_secret_key(parsed_config, settings)
        config.configure_password_update_alert(parsed_config, settings)
        config.configure_whitenoise(settings)
        webpack.configure_webpack(settings)
