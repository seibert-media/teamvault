import json
from configparser import ConfigParser

from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from teamvault.apps.secrets.context_processors import secrets_config
from teamvault.apps.secrets.enums import ContentType
from teamvault.apps.settings.config import configure_enabled_secret_types
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user, new_secret


def _config(value=None):
    """Return a minimal ConfigParser with an optional enabled_secret_types value."""
    cfg = ConfigParser()
    cfg.add_section('teamvault')
    if value is not None:
        cfg.set('teamvault', 'enabled_secret_types', value)
    return cfg


_TYPES_SUBSET = {**COMMON_OVERRIDES, 'TEAMVAULT_ENABLED_SECRET_TYPES': {'password', 'file'}}

TYPES_PASSWORD_ONLY = {**COMMON_OVERRIDES, 'TEAMVAULT_ENABLED_SECRET_TYPES': {'password'}}
TYPES_ALL = {**COMMON_OVERRIDES, 'TEAMVAULT_ENABLED_SECRET_TYPES': {'password', 'cc', 'file'}}


class SecretsConfigContextProcessorTests(SimpleTestCase):
    def test_enabled_secret_types_in_context(self):
        request = RequestFactory().get('/')
        with self.settings(**_TYPES_SUBSET):
            ctx = secrets_config(request)
        self.assertEqual(ctx['enabled_secret_types'], {'password', 'file'})


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
        with self.assertRaisesRegex(ImproperlyConfigured, 'banana'):
            configure_enabled_secret_types(_config('password,banana'), settings)

    def test_empty_value_raises(self):
        settings = FakeSettings()
        with self.assertRaisesRegex(ImproperlyConfigured, 'at least one valid type'):
            configure_enabled_secret_types(_config(''), settings)

    def test_whitespace_only_value_raises(self):
        settings = FakeSettings()
        with self.assertRaisesRegex(ImproperlyConfigured, 'at least one valid type'):
            configure_enabled_secret_types(_config('   '), settings)


@override_settings(**TYPES_PASSWORD_ONLY)
class SecretAddViewGuardTests(TestCase):
    def setUp(self):
        self.user = make_user('guard-user')
        self.client.force_login(self.user)

    def test_add_enabled_type_is_allowed(self):
        resp = self.client.get(reverse('secrets.secret-add', kwargs={'content_type': 'password'}))
        self.assertEqual(resp.status_code, 200)

    def test_add_disabled_type_returns_403(self):
        resp = self.client.get(reverse('secrets.secret-add', kwargs={'content_type': 'cc'}))
        self.assertEqual(resp.status_code, 403)

    def test_add_disabled_type_post_returns_403(self):
        resp = self.client.post(reverse('secrets.secret-add', kwargs={'content_type': 'file'}), data={})
        self.assertEqual(resp.status_code, 403)


@override_settings(**TYPES_PASSWORD_ONLY)
class SecretEditViewGuardTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('edit-guard-owner')
        cls.cc_secret = new_secret(cls.owner, name='cc-secret', content_type=ContentType.CC)

    def test_edit_disabled_type_returns_403(self):
        self.client.force_login(self.owner)
        resp = self.client.get(reverse('secrets.secret-edit', kwargs={'hashid': self.cc_secret.hashid}))
        self.assertEqual(resp.status_code, 403)

    @override_settings(**TYPES_ALL)
    def test_edit_enabled_type_is_allowed(self):
        self.client.force_login(self.owner)
        resp = self.client.get(reverse('secrets.secret-edit', kwargs={'hashid': self.cc_secret.hashid}))
        self.assertEqual(resp.status_code, 200)

    def test_edit_disabled_type_post_returns_403(self):
        self.client.force_login(self.owner)
        resp = self.client.post(reverse('secrets.secret-edit', kwargs={'hashid': self.cc_secret.hashid}), data={})
        self.assertEqual(resp.status_code, 403)


@override_settings(**TYPES_PASSWORD_ONLY)
class SecretListAPIGuardTests(TestCase):
    def setUp(self):
        self.user = make_user('api-guard-user')
        self.client.force_login(self.user)

    def test_create_enabled_type_is_allowed(self):
        resp = self.client.post(
            reverse('api.secret_list'),
            data=json.dumps({
                'content_type': 'password',
                'name': 'Test',
                'access_policy': 'discoverable',
                'secret_data': {'password': 'hunter2'},
            }),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 201)

    def test_create_disabled_type_returns_403(self):
        resp = self.client.post(
            reverse('api.secret_list'),
            data=json.dumps({
                'content_type': 'cc',
                'name': 'My Card',
                'access_policy': 'discoverable',
                'secret_data': {
                    'holder': 'Test',
                    'number': '4111111111111111',
                    'expiration_month': '12',
                    'expiration_year': '2030',
                    'security_code': '123',
                    'password': '',
                },
            }),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 403)


@override_settings(**TYPES_PASSWORD_ONLY)
class SecretDetailAPIGuardTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('api-edit-guard-owner')
        cls.cc_secret = new_secret(cls.owner, name='api-cc', content_type=ContentType.CC)

    def test_update_disabled_type_returns_403(self):
        self.client.force_login(self.owner)
        resp = self.client.patch(
            reverse('api.secret_detail', kwargs={'hashid': self.cc_secret.hashid}),
            data=json.dumps({'name': 'Renamed'}),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 403)

    @override_settings(**TYPES_ALL)
    def test_update_enabled_type_is_allowed(self):
        self.client.force_login(self.owner)
        resp = self.client.patch(
            reverse('api.secret_detail', kwargs={'hashid': self.cc_secret.hashid}),
            data=json.dumps({'name': 'Renamed'}),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
