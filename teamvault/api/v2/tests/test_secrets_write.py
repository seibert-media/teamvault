import json
from base64 import b64encode

from django.test import TestCase, override_settings

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry
from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret, SecretChange, SecretRevision
from teamvault.apps.secrets.services.revision import RevisionService
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user, new_secret


def auth_header(token_string):
    return {'HTTP_AUTHORIZATION': f'Bearer {token_string}'}


@override_settings(**COMMON_OVERRIDES)
class SecretCreateTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        _, cls.token = ApiToken.issue(user=cls.owner, name='writer', scopes=['secrets:write'])

    def _post(self, body, token=None):
        return self.client.post(
            '/api/v2/secrets/',
            data=json.dumps(body),
            content_type='application/json',
            **auth_header(token or self.token),
        )

    def test_create_password_returns_201_with_full_schema(self):
        response = self._post({
            'name': 'Prod DB',
            'content_type': 'password',
            'access_policy': 'any',
            'secret_data': {'password': 's3cr3t'},
        })
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertEqual(body['name'], 'Prod DB')
        self.assertEqual(body['content_type'], 'password')
        self.assertEqual(body['access_policy'], 'any')
        self.assertEqual(body['status'], 'ok')
        self.assertIsNotNone(body['current_payload'])
        secret = Secret.objects.get(hashid=body['hashid'])
        self.assertEqual(secret.content_type, ContentType.PASSWORD)
        self.assertEqual(secret.created_by, self.owner)

    def test_create_adds_creator_to_shared_users(self):
        body = self._post({'name': 'x', 'content_type': 'password', 'secret_data': {'password': 'pw'}}).json()
        secret = Secret.objects.get(hashid=body['hashid'])
        self.assertIn(self.owner, secret.shared_users.all())

    def test_create_defaults_access_policy_to_discoverable(self):
        body = self._post({'name': 'x', 'content_type': 'password', 'secret_data': {'password': 'pw'}}).json()
        secret = Secret.objects.get(hashid=body['hashid'])
        self.assertEqual(secret.access_policy, AccessPolicy.DISCOVERABLE)

    def test_create_credit_card(self):
        response = self._post({
            'name': 'Card',
            'content_type': 'credit_card',
            'secret_data': {
                'holder': 'Jane Doe',
                'number': '4111111111111111',
                'expiration_month': '12',
                'expiration_year': '2030',
                'security_code': '123',
            },
        })
        self.assertEqual(response.status_code, 201, response.content)
        secret = Secret.objects.get(hashid=response.json()['hashid'])
        self.assertEqual(secret.content_type, ContentType.CC)

    def test_create_file(self):
        response = self._post({
            'name': 'File',
            'content_type': 'file',
            'secret_data': {
                'filename': 'service-account.json',
                'file_content': b64encode(b'{}').decode('ascii'),
            },
        })
        self.assertEqual(response.status_code, 201, response.content)
        secret = Secret.objects.get(hashid=response.json()['hashid'])
        self.assertEqual(secret.content_type, ContentType.FILE)
        self.assertEqual(secret.filename, 'service-account.json')

    def test_create_records_secret_change_and_audit_log(self):
        body = self._post({'name': 'x', 'content_type': 'password', 'secret_data': {'password': 'pw'}}).json()
        secret = Secret.objects.get(hashid=body['hashid'])
        self.assertEqual(SecretChange.objects.filter(secret=secret).count(), 1)
        self.assertEqual(
            LogEntry.objects.filter(secret=secret, category=AuditLogCategoryChoices.SECRET_CHANGED).count(),
            1,
        )

    def test_create_missing_credit_card_field_returns_422(self):
        response = self._post({
            'name': 'Card',
            'content_type': 'credit_card',
            'secret_data': {'holder': 'Jane Doe'},
        })
        self.assertEqual(response.status_code, 422)

    def test_create_file_without_filename_returns_422(self):
        response = self._post({
            'name': 'File',
            'content_type': 'file',
            'secret_data': {'file_content': b64encode(b'{}').decode('ascii')},
        })
        self.assertEqual(response.status_code, 422)

    def test_create_unknown_content_type_returns_422(self):
        response = self._post({'name': 'x', 'content_type': 'bogus', 'secret_data': {'password': 'pw'}})
        self.assertEqual(response.status_code, 422)

    def test_create_password_payload_for_credit_card_returns_422(self):
        response = self._post({'name': 'x', 'content_type': 'credit_card', 'secret_data': {'password': 'pw'}})
        self.assertEqual(response.status_code, 422)

    def test_create_requires_write_scope(self):
        _, read_token = ApiToken.issue(user=self.owner, name='reader', scopes=['secrets:read'])
        response = self._post(
            {'name': 'x', 'content_type': 'password', 'secret_data': {'password': 'pw'}},
            token=read_token,
        )
        self.assertEqual(response.status_code, 403)

    def test_create_without_token_returns_401(self):
        response = self.client.post(
            '/api/v2/secrets/',
            data=json.dumps({'name': 'x', 'content_type': 'password', 'secret_data': {'password': 'pw'}}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 401)


@override_settings(**COMMON_OVERRIDES)
class SecretUpdateTest(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        _, self.token = ApiToken.issue(user=self.owner, name='writer', scopes=['secrets:write'])
        self.secret = new_secret(
            self.owner,
            content_type=ContentType.PASSWORD,
            payload={'password': 'old'},
            access_policy=AccessPolicy.ANY,
            name='pw',
        )

    def _patch(self, hashid, body, token=None):
        return self.client.patch(
            f'/api/v2/secrets/{hashid}',
            data=json.dumps(body),
            content_type='application/json',
            **auth_header(token or self.token),
        )

    def test_update_metadata(self):
        response = self._patch(self.secret.hashid, {'name': 'renamed', 'url': 'https://x'})
        self.assertEqual(response.status_code, 200, response.content)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.name, 'renamed')
        self.assertEqual(self.secret.url, 'https://x')

    def test_update_payload_creates_new_revision(self):
        old_revision_id = self.secret.current_revision_id
        response = self._patch(self.secret.hashid, {'secret_data': {'password': 'new'}})
        self.assertEqual(response.status_code, 200, response.content)
        self.secret.refresh_from_db()
        self.assertNotEqual(self.secret.current_revision_id, old_revision_id)

    def test_update_access_policy(self):
        response = self._patch(self.secret.hashid, {'access_policy': 'hidden'})
        self.assertEqual(response.status_code, 200, response.content)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.access_policy, AccessPolicy.HIDDEN)

    def test_update_content_type_change_returns_422(self):
        response = self._patch(self.secret.hashid, {'content_type': 'file'})
        self.assertEqual(response.status_code, 422)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.content_type, ContentType.PASSWORD)

    def test_update_same_content_type_is_allowed(self):
        response = self._patch(self.secret.hashid, {'content_type': 'password', 'name': 'x'})
        self.assertEqual(response.status_code, 200, response.content)

    def test_update_same_plaintext_reuses_revision(self):
        # First write the payload through the v2 path so the stored plaintext shape matches,
        # then re-send the identical payload and assert dedup reuses the revision.
        first = self._patch(self.secret.hashid, {'secret_data': {'password': 'same'}})
        self.assertEqual(first.status_code, 200, first.content)
        self.secret.refresh_from_db()
        old_revision_id = self.secret.current_revision_id
        old_count = SecretRevision.objects.filter(secret=self.secret).count()

        second = self._patch(self.secret.hashid, {'secret_data': {'password': 'same'}})
        self.assertEqual(second.status_code, 200, second.content)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.current_revision_id, old_revision_id)
        self.assertEqual(SecretRevision.objects.filter(secret=self.secret).count(), old_count)

    def test_update_unknown_hashid_returns_404(self):
        self.assertEqual(self._patch('nope', {'name': 'x'}).status_code, 404)

    def test_update_invisible_secret_returns_404(self):
        other = make_user('other')
        hidden = new_secret(other, access_policy=AccessPolicy.HIDDEN, name='Hidden')
        self.assertEqual(self._patch(hidden.hashid, {'name': 'x'}).status_code, 404)

    def test_update_visible_but_unreadable_returns_403(self):
        other = make_user('other')
        discoverable = new_secret(other, access_policy=AccessPolicy.DISCOVERABLE, name='Disc')
        self.assertEqual(self._patch(discoverable.hashid, {'name': 'x'}).status_code, 403)

    def test_update_requires_write_scope(self):
        _, read_token = ApiToken.issue(user=self.owner, name='reader', scopes=['secrets:read'])
        self.assertEqual(self._patch(self.secret.hashid, {'name': 'x'}, token=read_token).status_code, 403)


@override_settings(**COMMON_OVERRIDES)
class SecretDeleteTest(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        _, self.token = ApiToken.issue(user=self.owner, name='writer', scopes=['secrets:write'])
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.ANY, name='pw')

    def _delete(self, hashid, token=None):
        return self.client.delete(f'/api/v2/secrets/{hashid}', **auth_header(token or self.token))

    def test_delete_returns_204_and_soft_deletes(self):
        response = self._delete(self.secret.hashid)
        self.assertEqual(response.status_code, 204)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.status, SecretStatus.DELETED)

    def test_deleted_secret_disappears_from_list(self):
        self._delete(self.secret.hashid)
        _, read_token = ApiToken.issue(user=self.owner, name='reader', scopes=['secrets:read'])
        body = self.client.get('/api/v2/secrets/?page_size=200', **auth_header(read_token)).json()
        self.assertNotIn(self.secret.hashid, {item['hashid'] for item in body['results']})

    def test_delete_unknown_hashid_returns_404(self):
        self.assertEqual(self._delete('nope').status_code, 404)

    def test_delete_requires_write_scope(self):
        _, read_token = ApiToken.issue(user=self.owner, name='reader', scopes=['secrets:read'])
        self.assertEqual(self._delete(self.secret.hashid, token=read_token).status_code, 403)


@override_settings(**COMMON_OVERRIDES)
class WriteScopeCannotReadDataTest(TestCase):
    """A secrets:write-only token can rotate a payload but cannot read any payload back."""

    def setUp(self):
        self.owner = make_user('owner')
        _, self.token = ApiToken.issue(user=self.owner, name='writer', scopes=['secrets:write'])
        self.secret = new_secret(self.owner, payload={'password': 'old'}, access_policy=AccessPolicy.ANY, name='pw')

    def test_write_token_can_rotate_but_not_read(self):
        rotate = self.client.patch(
            f'/api/v2/secrets/{self.secret.hashid}',
            data=json.dumps({'secret_data': {'password': 'new'}}),
            content_type='application/json',
            **auth_header(self.token),
        )
        self.assertEqual(rotate.status_code, 200, rotate.content)
        read = self.client.get(f'/api/v2/secrets/{self.secret.hashid}/data', **auth_header(self.token))
        self.assertEqual(read.status_code, 403)


@override_settings(**COMMON_OVERRIDES)
class FileWriteReadRoundTripTest(TestCase):
    """A file secret created via v2 reads back with the same filename and base64 content."""

    def setUp(self):
        self.owner = make_user('owner')
        _, self.token = ApiToken.issue(user=self.owner, name='rw', scopes=['secrets:write', 'secrets:data:read'])

    def test_create_file_then_read_data_round_trips(self):
        file_bytes = b'{"key": "value"}'
        encoded = b64encode(file_bytes).decode('ascii')
        create = self.client.post(
            '/api/v2/secrets/',
            data=json.dumps({
                'name': 'File',
                'content_type': 'file',
                'access_policy': 'any',
                'secret_data': {'filename': 'service-account.json', 'file_content': encoded},
            }),
            content_type='application/json',
            **auth_header(self.token),
        )
        self.assertEqual(create.status_code, 201, create.content)
        hashid = create.json()['hashid']

        read = self.client.get(f'/api/v2/secrets/{hashid}/data', **auth_header(self.token))
        self.assertEqual(read.status_code, 200, read.content)
        body = read.json()
        self.assertEqual(body['filename'], 'service-account.json')
        self.assertEqual(body['file_content'], encoded)


@override_settings(**COMMON_OVERRIDES)
class FileCrossShapeDedupTest(TestCase):
    """A file payload stored in v1's serialized shape dedups against an identical v2 PATCH."""

    def setUp(self):
        self.owner = make_user('owner')
        _, self.token = ApiToken.issue(user=self.owner, name='writer', scopes=['secrets:write'])

    def test_v2_patch_dedups_against_v1_stored_file_payload(self):
        from teamvault.apps.secrets.api.serializers import serialize_file

        file_bytes = b'identical-file-bytes'
        encoded = b64encode(file_bytes).decode('ascii')

        secret = new_secret(
            self.owner,
            content_type=ContentType.FILE,
            access_policy=AccessPolicy.ANY,
            name='File',
            filename='doc.bin',
            payload=serialize_file({'filename': 'doc.bin', 'file_content': file_bytes}),
        )
        old_revision_id = secret.current_revision_id
        old_count = SecretRevision.objects.filter(secret=secret).count()

        response = self.client.patch(
            f'/api/v2/secrets/{secret.hashid}',
            data=json.dumps({'secret_data': {'filename': 'doc.bin', 'file_content': encoded}}),
            content_type='application/json',
            **auth_header(self.token),
        )
        self.assertEqual(response.status_code, 200, response.content)
        secret.refresh_from_db()
        self.assertEqual(secret.current_revision_id, old_revision_id)
        self.assertEqual(SecretRevision.objects.filter(secret=secret).count(), old_count)


@override_settings(**COMMON_OVERRIDES)
class WriteV1ParityTest(TestCase):
    """A secret created via v2 is identical (history, shares, audit) to one created via v1."""

    def setUp(self):
        self.owner = make_user('owner')
        _, self.token = ApiToken.issue(user=self.owner, name='writer', scopes=['secrets:write'])

    def _create_via_v1(self):
        from teamvault.apps.secrets.api.serializers import SecretSerializer

        class _Req:
            user = self.owner

        ser = SecretSerializer(
            data={
                'name': 'parity',
                'access_policy': 'any',
                'content_type': 'password',
                'secret_data': {'password': 'pw'},
            },
            context={'request': _Req()},
        )
        self.assertTrue(ser.is_valid(), ser.errors)
        instance = ser.save(created_by=self.owner)
        RevisionService.save_payload(secret=instance, actor=self.owner, payload=instance._data, skip_acl=True)
        instance.refresh_from_db()
        return instance

    def test_v2_create_matches_v1_create(self):
        v1 = self._create_via_v1()
        response = self.client.post(
            '/api/v2/secrets/',
            data=json.dumps({
                'name': 'parity',
                'access_policy': 'any',
                'content_type': 'password',
                'secret_data': {'password': 'pw'},
            }),
            content_type='application/json',
            **auth_header(self.token),
        )
        self.assertEqual(response.status_code, 201, response.content)
        v2 = Secret.objects.get(hashid=response.json()['hashid'])

        self.assertEqual(v2.content_type, v1.content_type)
        self.assertEqual(v2.access_policy, v1.access_policy)
        self.assertEqual(v2.created_by, v1.created_by)
        self.assertEqual(
            list(v2.shared_users.values_list('username', flat=True)),
            list(v1.shared_users.values_list('username', flat=True)),
        )
        self.assertEqual(
            SecretChange.objects.filter(secret=v2).count(),
            SecretChange.objects.filter(secret=v1).count(),
        )
        self.assertEqual(
            LogEntry.objects.filter(secret=v2, category=AuditLogCategoryChoices.SECRET_CHANGED).count(),
            LogEntry.objects.filter(secret=v1, category=AuditLogCategoryChoices.SECRET_CHANGED).count(),
        )
