from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIRequestFactory
from teamvault.apps.secrets.api.serializers import (
    SecretDetailSerializer,
    SecretRevisionSerializer,
    SecretSerializer,
    SharedSecretDataSerializer,
)
from teamvault.apps.secrets.enums import AccessPolicy, ContentType
from teamvault.apps.secrets.models import AccessPermissionTypes, Secret, SharedSecretData
from teamvault.apps.secrets.services.revision import RevisionService

from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class SecretSerializerCreateTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.factory = APIRequestFactory()

    def test_create_password_secret_sets_self_share_and_content_type_and_stashes_payload(self):
        req = self.factory.post('/api/secrets/')
        req.user = self.owner

        ser = SecretSerializer(
            data={
                'name': 'pw',
                'access_policy': 'discoverable',
                'content_type': 'password',
                'secret_data': {'password': 'p@ss'},
            },
            context={'request': req},
        )
        self.assertTrue(ser.is_valid(), ser.errors)

        inst: Secret = ser.save(created_by=self.owner)

        # Serializer.create() does NOT write a revision; it sets ._data and M2M share.
        self.assertIsNone(inst.current_revision)
        self.assertEqual(inst.content_type, ContentType.PASSWORD)
        self.assertEqual(inst._data, {'password': 'p@ss', 'otp_key_data': ''})
        # creator self-share:
        self.assertTrue(inst.shared_users.filter(pk=self.owner.pk).exists())

    def test_missing_secret_data_is_rejected_on_save(self):
        req = self.factory.post('/api/secrets/')
        req.user = self.owner

        ser = SecretSerializer(
            data={
                'name': 'pw',
                'access_policy': 'discoverable',
                'content_type': 'password',
                # secret_data omitted → is_valid passes, but create() raises
            },
            context={'request': req},
        )
        self.assertTrue(ser.is_valid(), ser.errors)
        with self.assertRaises(ValidationError):
            ser.save(created_by=self.owner)


@override_settings(**COMMON_OVERRIDES)
class SecretSerializerRepresentationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        # Helper writes an initial revision and grants owner read access
        cls.secret = new_secret(cls.owner, name='repr-pw', access_policy=AccessPolicy.DISCOVERABLE)
        cls.factory = APIRequestFactory()

    def test_representation_maps_enums_urls_and_sets_data_readable_for_owner(self):
        req = self.factory.get('/api/secrets/')
        req.user = self.owner

        ser = SecretSerializer(instance=self.secret, context={'request': req})
        rep = ser.data

        # enums → string
        self.assertIn(rep['access_policy'], {'any', 'discoverable', 'hidden'})
        self.assertEqual(rep['content_type'], 'password')
        self.assertIn(rep['status'], {'ok', 'deleted', 'needs_changing'})

        # links
        self.assertTrue(rep['api_url'].endswith(f'/api/secrets/{self.secret.hashid}/'))
        self.assertTrue(rep['web_url'])  # full web URL string
        self.assertTrue(
            rep['current_revision'].endswith(f'/api/secret-revisions/{self.secret.current_revision.hashid}/')
        )

        # readable flag is actually an enum value here, not strict bool
        self.assertEqual(rep['data_readable'], AccessPermissionTypes.ALLOWED)


@override_settings(**COMMON_OVERRIDES)
class SecretDetailSerializerUpdateTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.secret = new_secret(cls.owner, name='upd-pw')  # has a current revision
        cls.factory = APIRequestFactory()

    def test_update_allows_metadata_and_payload_and_keeps_content_type(self):
        req = self.factory.patch('/api/secrets/')
        req.user = self.owner

        ser = SecretDetailSerializer(
            instance=self.secret,
            data={'name': 'renamed', 'secret_data': {'password': 'n3w'}},
            partial=True,
            context={'request': req},
        )
        self.assertTrue(ser.is_valid(), ser.errors)
        updated: Secret = ser.save()

        # Serializer.update() keeps content_type unchanged and stashes new _data;
        # it does not itself create a new revision.
        self.assertEqual(updated.content_type, ContentType.PASSWORD)
        self.assertEqual(updated.name, 'renamed')
        self.assertEqual(updated._data, {'password': 'n3w', 'otp_key_data': ''})


@override_settings(**COMMON_OVERRIDES)
class SecretRevisionSerializerTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.secret = new_secret(cls.owner, name='pw')
        # add a second payload to ensure we serialize a real revision instance
        RevisionService.save_payload(secret=cls.secret, actor=cls.owner, payload={'password': 'two'})
        cls.rev = cls.secret.current_revision
        cls.factory = APIRequestFactory()

    def test_revision_serializer_includes_data_url(self):
        req = self.factory.get('/api/secret-revisions/')
        req.user = self.owner

        ser = SecretRevisionSerializer(instance=self.rev, context={'request': req})
        rep = ser.data
        self.assertTrue(rep['api_url'].endswith(f'/api/secret-revisions/{self.rev.hashid}/'))
        # The reversed name returns ".../data" (no trailing slash)
        self.assertTrue(rep['data_url'].endswith(f'/api/secret-revisions/{self.rev.hashid}/data'))


@override_settings(**COMMON_OVERRIDES)
class SharedSecretDataSerializerTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.bob = make_user('bob')
        cls.secret = new_secret(cls.owner, name='share-me')
        cls.factory = APIRequestFactory()
        cls.team = Group.objects.create(name='team')

    def _ser(self, data):
        req = self.factory.post('/api/shares/')
        req.user = self.owner
        # Always include both keys with possibly None to match validate()’s direct indexing
        if 'group' not in data:
            data['group'] = None
        if 'user' not in data:
            data['user'] = None
        return SharedSecretDataSerializer(data=data, context={'request': req, 'secret': self.secret})

    def test_must_choose_exactly_one_of_user_or_group(self):
        # valid: user only
        ser = self._ser({
            'user': self.bob.username,
            'grant_description': 'only-user',
            'granted_until': None,
        })
        self.assertTrue(ser.is_valid(), ser.errors)

        # invalid: both user and group
        ser = self._ser({
            'user': self.bob.username,
            'group': self.team.name,
            'grant_description': 'both',
            'granted_until': None,
        })
        self.assertFalse(ser.is_valid())
        self.assertIn('non_field_errors', ser.errors)

        # invalid: neither user nor group
        ser = self._ser({
            'grant_description': 'neither',
            'granted_until': None,
        })
        self.assertFalse(ser.is_valid())
        self.assertIn('non_field_errors', ser.errors)

    def test_uniqueness_guard(self):
        # first share
        SharedSecretData.objects.create(secret=self.secret, user=self.bob, granted_by=self.owner)

        # duplicate share for same user → non_field_errors
        ser = self._ser({
            'user': self.bob.username,
            'grant_description': 'dup',
            'granted_until': None,
        })
        self.assertFalse(ser.is_valid())
        self.assertIn('non_field_errors', ser.errors)

    def test_valid_user_share(self):
        charlie = make_user('charlie')
        ser = self._ser({
            'user': charlie.username,
            'grant_description': 'ok',
            'granted_until': None,
        })
        self.assertTrue(ser.is_valid(), ser.errors)
