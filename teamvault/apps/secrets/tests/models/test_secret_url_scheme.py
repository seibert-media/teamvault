from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from teamvault.apps.secrets.models import validate_url
from ..utils import COMMON_OVERRIDES, make_user, new_secret

SCRIPT_URLS = [
    'javascript://%0Aalert(1)',
    'JavaScript://%0Aalert(1)',
    '\tjavascript://%0Aalert(1)',
    ' javascript://%0Aalert(1)',
    'java\nscript://%0Aalert(1)',
    'data://text/html,<script>alert(1)</script>',
    'vbscript://msgbox(1)',
]

NON_HTTP_URLS_IN_USE = [
    'ssh://host.example.com',
    'rdp://host.example.com',
    'jdbc:postgresql://db.example.com/app',
    'jdbc:jtds:sqlserver://db.example.com',
    'ldaps://ldap.example.com',
    ' http://leading-space.example.com',
    'PROD: https://prod.example.com',
]


class ValidateUrlTests(TestCase):
    def test_rejects_script_schemes_regardless_of_case_and_whitespace(self):
        for url in SCRIPT_URLS:
            with self.subTest(url=url), self.assertRaises(ValidationError):
                validate_url(url)

    def test_accepts_non_http_schemes_in_use(self):
        for url in NON_HTTP_URLS_IN_USE + ['https://example.com']:
            with self.subTest(url=url):
                validate_url(url)

    def test_rejects_value_without_scheme_separator(self):
        with self.assertRaises(ValidationError):
            validate_url('example.com')


@override_settings(**COMMON_OVERRIDES)
class SecretUrlIsLinkableTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')

    def _secret_with_url(self, url):
        # Secret.save() does not run field validators, so this mirrors rows
        # stored before the validator caught these variants.
        secret = new_secret(self.owner)
        secret.url = url
        secret.save()
        return secret

    def test_script_urls_are_not_linkable(self):
        for url in SCRIPT_URLS:
            with self.subTest(url=url):
                self.assertFalse(self._secret_with_url(url).url_is_linkable)

    def test_other_schemes_are_linkable(self):
        for url in NON_HTTP_URLS_IN_USE + ['https://example.com']:
            with self.subTest(url=url):
                self.assertTrue(self._secret_with_url(url).url_is_linkable)

    def test_empty_url_is_not_linkable(self):
        for url in [None, '']:
            with self.subTest(url=url):
                self.assertFalse(self._secret_with_url(url).url_is_linkable)
