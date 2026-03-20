from configparser import ConfigParser

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from teamvault.apps.settings.config import configure_enabled_secret_types


def _config(value=None):
    """Return a minimal ConfigParser with an optional enabled_secret_types value."""
    cfg = ConfigParser()
    cfg.add_section('teamvault')
    if value is not None:
        cfg.set('teamvault', 'enabled_secret_types', value)
    return cfg


class FakeSettings:
    pass


class ConfigureEnabledSecretTypesTests(SimpleTestCase):
    def test_all_types_enabled_when_key_absent(self):
        settings = FakeSettings()
        configure_enabled_secret_types(_config(), settings)
        self.assertEqual(settings.TEAMVAULT_ENABLED_SECRET_TYPES, {'password', 'cc', 'file'})

    def test_subset_of_types(self):
        settings = FakeSettings()
        configure_enabled_secret_types(_config('password,file'), settings)
        self.assertEqual(settings.TEAMVAULT_ENABLED_SECRET_TYPES, {'password', 'file'})

    def test_single_type(self):
        settings = FakeSettings()
        configure_enabled_secret_types(_config('cc'), settings)
        self.assertEqual(settings.TEAMVAULT_ENABLED_SECRET_TYPES, {'cc'})

    def test_whitespace_and_case_are_normalised(self):
        settings = FakeSettings()
        configure_enabled_secret_types(_config(' PASSWORD , CC '), settings)
        self.assertEqual(settings.TEAMVAULT_ENABLED_SECRET_TYPES, {'password', 'cc'})

    def test_invalid_type_raises(self):
        settings = FakeSettings()
        with self.assertRaises(ImproperlyConfigured):
            configure_enabled_secret_types(_config('password,banana'), settings)

    def test_empty_value_raises(self):
        settings = FakeSettings()
        with self.assertRaises(ImproperlyConfigured):
            configure_enabled_secret_types(_config(''), settings)

    def test_whitespace_only_value_raises(self):
        settings = FakeSettings()
        with self.assertRaises(ImproperlyConfigured):
            configure_enabled_secret_types(_config('   '), settings)
