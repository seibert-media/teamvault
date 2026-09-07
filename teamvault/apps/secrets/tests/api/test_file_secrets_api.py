from base64 import b64decode, b64encode
from json import loads

from cryptography.fernet import Fernet
from django.conf import settings
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from teamvault.apps.secrets.enums import ContentType
from teamvault.apps.secrets.models import Secret
from ..utils import COMMON_OVERRIDES, make_user, new_secret

FILE_BYTES = b'\x00\x01hello-file\xff'
FILE_B64 = b64encode(FILE_BYTES).decode('ascii')


def stored_payload(revision) -> dict:
    return loads(Fernet(settings.TEAMVAULT_SECRET_KEY).decrypt(revision.encrypted_data))


@override_settings(**COMMON_OVERRIDES)
class FileSecretApiTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.api_client = APIClient()
        self.api_client.force_authenticate(user=self.owner)

    def _create(self, **overrides):
        body = {
            'name': 'a-file',
            'access_policy': 'discoverable',
            'content_type': 'file',
            'filename': 'hello.bin',
            'secret_data': {'file_content': FILE_B64},
        }
        body.update(overrides)
        return self.api_client.post(reverse('api.secret_list'), body, format='json')

    def test_creating_a_file_secret_succeeds(self):
        response = self._create()
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, getattr(response, 'data', None))
        secret = Secret.objects.get(name='a-file')
        self.assertEqual(secret.content_type, ContentType.FILE)
        self.assertEqual(secret.filename, 'hello.bin')

    def test_created_payload_matches_the_format_migration_0039_enforces(self):
        self._create()
        secret = Secret.objects.get(name='a-file')
        payload = secret.current_revision.peek_data(self.owner)
        self.assertEqual(payload, FILE_BYTES)

    def test_created_payload_has_no_filename_key(self):
        self._create()
        secret = Secret.objects.get(name='a-file')
        raw = stored_payload(secret.current_revision)
        self.assertEqual(set(raw), {'file_content'})
        self.assertEqual(b64decode(raw['file_content']), FILE_BYTES)

    def test_created_secret_representation_includes_the_filename(self):
        response = self._create()
        self.assertEqual(response.data['filename'], 'hello.bin')

    def test_download_view_serves_the_uploaded_bytes_and_filename(self):
        self._create()
        secret = Secret.objects.get(name='a-file')
        web_client = Client()
        web_client.force_login(self.owner)
        response = web_client.get(reverse('secrets.secret-download', args=[secret.hashid]))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.content, FILE_BYTES)
        self.assertEqual(response['Content-Disposition'], "attachment; filename*=UTF-8''hello.bin")

    def test_reading_back_through_the_data_endpoint_returns_the_uploaded_bytes(self):
        self._create()
        secret = Secret.objects.get(name='a-file')
        response = self.api_client.get(reverse('api.secret-revision_data', args=[secret.current_revision.hashid]))
        self.assertEqual(response.status_code, status.HTTP_200_OK, getattr(response, 'data', None))
        self.assertEqual(b64decode(response.data['file']), FILE_BYTES)

    def test_creating_a_file_secret_without_a_filename_names_the_field(self):
        response = self._create(filename=None)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, getattr(response, 'data', None))
        self.assertIn('filename', response.data)
        self.assertFalse(Secret.objects.filter(name='a-file').exists())

    def test_file_content_that_is_not_base64_is_a_validation_error(self):
        response = self._create(secret_data={'file_content': 'not base64!!'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, getattr(response, 'data', None))
        self.assertIn('file_content', response.content.decode())
        self.assertFalse(Secret.objects.filter(name='a-file').exists())

    def test_a_filename_on_a_non_file_secret_is_rejected(self):
        response = self._create(
            content_type='password',
            secret_data={'password': 'XYZ'},
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, getattr(response, 'data', None))
        self.assertIn('filename', response.data)


@override_settings(**COMMON_OVERRIDES)
class FileSecretUpdateApiTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.api_client = APIClient()
        self.api_client.force_authenticate(user=self.owner)
        self.secret = new_secret(self.owner, ContentType.FILE, name='a-file', filename='hello.bin')

    def _patch(self, body):
        return self.api_client.patch(
            reverse('api.secret_detail', args=[self.secret.hashid]),
            body,
            format='json',
        )

    def test_updating_the_content_round_trips_the_new_bytes(self):
        response = self._patch({'secret_data': {'file_content': FILE_B64}})
        self.assertEqual(response.status_code, status.HTTP_200_OK, getattr(response, 'data', None))
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.current_revision.peek_data(self.owner), FILE_BYTES)

    def test_updating_the_content_alone_keeps_the_filename(self):
        self._patch({'secret_data': {'file_content': FILE_B64}})
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.filename, 'hello.bin')

    def test_updating_the_filename_alone_leaves_the_payload_untouched(self):
        revision_before = self.secret.current_revision_id
        response = self._patch({'filename': 'renamed.bin'})
        self.assertEqual(response.status_code, status.HTTP_200_OK, getattr(response, 'data', None))
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.filename, 'renamed.bin')
        self.assertEqual(self.secret.current_revision_id, revision_before)

    def test_updating_both_round_trips_content_and_filename(self):
        response = self._patch({'filename': 'renamed.bin', 'secret_data': {'file_content': FILE_B64}})
        self.assertEqual(response.status_code, status.HTTP_200_OK, getattr(response, 'data', None))
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.filename, 'renamed.bin')
        self.assertEqual(self.secret.current_revision.peek_data(self.owner), FILE_BYTES)

    def test_the_representation_exposes_the_filename(self):
        response = self.api_client.get(reverse('api.secret_detail', args=[self.secret.hashid]))
        self.assertEqual(response.data['filename'], 'hello.bin')

    def test_updating_with_invalid_base64_leaves_the_revision_alone(self):
        revision_before = self.secret.current_revision_id
        response = self._patch({'secret_data': {'file_content': 'not base64!!'}})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, getattr(response, 'data', None))
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.current_revision_id, revision_before)


@override_settings(**COMMON_OVERRIDES)
class ContentTypePersistenceTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.api_client = APIClient()
        self.api_client.force_authenticate(user=self.owner)

    def _create(self, name, content_type, secret_data, **extra):
        return self.api_client.post(
            reverse('api.secret_list'),
            {
                'name': name,
                'access_policy': 'discoverable',
                'content_type': content_type,
                'secret_data': secret_data,
                **extra,
            },
            format='json',
        )

    def test_a_credit_card_is_stored_as_a_credit_card(self):
        response = self._create(
            'a-cc',
            'cc',
            {
                'holder': 'Jane Doe',
                'expiration_month': '12',
                'expiration_year': '2030',
                'number': '4111111111111111',
                'security_code': '123',
                'password': '',
            },
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, getattr(response, 'data', None))
        self.assertEqual(Secret.objects.get(name='a-cc').content_type, ContentType.CC)

    def test_a_file_is_stored_as_a_file(self):
        response = self._create('a-file', 'file', {'file_content': FILE_B64}, filename='hello.bin')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, getattr(response, 'data', None))
        self.assertEqual(Secret.objects.get(name='a-file').content_type, ContentType.FILE)

    def test_a_password_is_stored_as_a_password(self):
        response = self._create('a-password', 'password', {'password': 'XYZ'})

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, getattr(response, 'data', None))
        self.assertEqual(Secret.objects.get(name='a-password').content_type, ContentType.PASSWORD)
