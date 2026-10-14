from datetime import timedelta

from django.core.exceptions import PermissionDenied
from django.test import TestCase, override_settings
from django.utils.timezone import now

from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import SecretChange, SharedSecretData
from teamvault.apps.secrets.services.revision import RevisionService
from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class RevisionServiceAclTests(TestCase):
    """
    Same thing as the "SecretEditPermissionTests"/"SecretEditPermissionAPITests".
    Temp users shouldn't escalate privileges, but on a model level using save_payload(actor=XYZ).
    """

    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.temp_reader = make_user('temp_reader')

    def setUp(self):
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN)
        SharedSecretData.objects.create(
            secret=self.secret,
            user=self.temp_reader,
            granted_by=self.owner,
            granted_until=now() + timedelta(days=1),
        )

    def test_save_payload_rejects_temporary_reader(self):
        revision_before = self.secret.current_revision_id
        with self.assertRaises(PermissionDenied):
            RevisionService.save_payload(secret=self.secret, actor=self.temp_reader, payload={'password': 'new'})
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.current_revision_id, revision_before)

    def test_restore_to_change_rejects_temporary_reader(self):
        first_change = SecretChange.objects.filter(secret=self.secret).earliest('created')
        RevisionService.save_payload(secret=self.secret, actor=self.owner, payload={'password': 'v2'})
        revision_before = self.secret.current_revision_id

        with self.assertRaises(PermissionDenied):
            RevisionService.restore_to_change(secret=self.secret, actor=self.temp_reader, change=first_change)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.current_revision_id, revision_before)
