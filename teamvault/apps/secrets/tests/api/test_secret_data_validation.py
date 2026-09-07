from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret
from ..utils import COMMON_OVERRIDES, OTP_KEY_DATA, OTP_SECRET, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class MissingSecretDataFieldTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.api_client = APIClient()
        self.api_client.force_authenticate(user=self.owner)

    def _create(self, content_type: str, secret_data: dict, name: str = 'incomplete'):
        return self.api_client.post(
            reverse('api.secret_list'),
            {
                'name': name,
                'access_policy': 'discoverable',
                'content_type': content_type,
                'secret_data': secret_data,
            },
            format='json',
        )

    def _patch(self, secret: Secret, secret_data: dict):
        return self.api_client.patch(
            reverse('api.secret_detail', args=[secret.hashid]),
            {'secret_data': secret_data},
            format='json',
        )

    def assertNamesMissingField(self, response, field: str):
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, getattr(response, 'data', None))
        self.assertIn(field, response.content.decode())

    def test_creating_a_password_without_a_password_names_the_field(self):
        response = self._create('password', {'otp_key_data': OTP_KEY_DATA})

        self.assertNamesMissingField(response, 'password')
        self.assertFalse(Secret.objects.filter(name='incomplete').exists())

    def test_creating_a_file_without_a_filename_names_the_field(self):
        response = self._create('file', {'file_content': 'aGVsbG8='})
        self.assertNamesMissingField(response, 'filename')

    def test_creating_a_file_without_file_content_names_the_field(self):
        response = self._create('file', {'filename': 'hello.bin'})
        self.assertNamesMissingField(response, 'file_content')

    def test_creating_a_credit_card_without_a_field_names_it(self):
        response = self._create('cc', {'holder': 'Jane'})
        self.assertNamesMissingField(response, 'expiration_month')

    def test_updating_a_file_without_a_filename_names_the_field(self):
        secret = new_secret(self.owner, ContentType.FILE, name='a-file')
        response = self._patch(secret, {'file_content': 'aGVsbG8='})
        self.assertNamesMissingField(response, 'filename')

    def test_updating_a_password_that_has_no_revision_to_inherit_from_names_the_field(self):
        secret = Secret.objects.create(
            name='no-revision',
            created_by=self.owner,
            content_type=ContentType.PASSWORD,
            access_policy=AccessPolicy.ANY,
            status=SecretStatus.OK,
        )
        response = self._patch(secret, {'otp_key_data': OTP_KEY_DATA})
        self.assertNamesMissingField(response, 'password')


@override_settings(**COMMON_OVERRIDES)
class PartialPasswordUpdateTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.api_client = APIClient()
        self.api_client.force_authenticate(user=self.owner)
        self.secret = new_secret(self.owner, name='inherits-password', payload={'password': 'XYZ'})

    def test_adding_an_otp_key_keeps_the_existing_password(self):
        response = self.api_client.patch(
            reverse('api.secret_detail', args=[self.secret.hashid]),
            {'secret_data': {'otp_key_data': OTP_KEY_DATA}},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, getattr(response, 'data', None))
        self.secret.refresh_from_db()
        payload = self.secret.current_revision.peek_data(self.owner)
        self.assertEqual(payload['password'], 'XYZ')
        self.assertEqual(payload['otp_key'], OTP_SECRET)
        self.assertTrue(self.secret.current_revision.otp_key_set)
