import string

from django.test import TestCase, override_settings

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user

URL = '/api/v2/password-suggestion'


def auth_header(token_string):
    return {'HTTP_AUTHORIZATION': f'Bearer {token_string}'}


@override_settings(**COMMON_OVERRIDES)
class PasswordSuggestionTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = make_user('alice')
        _, cls.token = ApiToken.issue(user=cls.user, name='any key', scopes=['secrets:read'])

    def test_anonymous_request_is_rejected(self):
        response = self.client.get(URL)
        self.assertEqual(response.status_code, 401)

    def test_any_valid_token_works(self):
        response = self.client.get(URL, **auth_header(self.token))
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertIn('password', body)
        self.assertIsInstance(body['password'], str)
        self.assertTrue(body['password'])

    @override_settings(PASSWORD_LENGTH=20, PASSWORD_DIGITS=4, PASSWORD_UPPER=2, PASSWORD_LOWER=2, PASSWORD_SPECIAL=2)
    def test_respects_configured_length(self):
        response = self.client.get(URL, **auth_header(self.token))
        self.assertEqual(len(response.json()['password']), 20)

    @override_settings(PASSWORD_LENGTH=12, PASSWORD_DIGITS=0, PASSWORD_UPPER=0, PASSWORD_LOWER=12, PASSWORD_SPECIAL=0)
    def test_respects_configured_character_classes(self):
        password = self.client.get(URL, **auth_header(self.token)).json()['password']
        self.assertTrue(all(c in string.ascii_lowercase for c in password))
