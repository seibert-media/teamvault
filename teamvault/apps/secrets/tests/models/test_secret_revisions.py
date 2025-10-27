from copy import copy

from django.test import TestCase, override_settings

from teamvault.apps.secrets.models import SecretRevision, SecretChange
from teamvault.apps.secrets.services.revision import RevisionService
from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class RevisionHistoryTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.secret = new_secret(self.owner)

    def test_payload_and_metadata_timeline(self):
        """Create two payload revisions + one pure metadata change → verify
        object counts and diff rendering assumptions."""
        s = self.secret

        # 2nd REVISION: payload update
        RevisionService.save_payload(
            secret=s,
            actor=self.owner,
            payload={'password': 'second‑pw'}
        )
        self.assertEqual(SecretRevision.objects.filter(secret=s).count(), 2)
        # Two distinct payload revisions
        self.assertEqual(SecretRevision.objects.filter(secret=s).count(), 2)

        # 3rd change: ONLY metadata update
        s.description = 'New description'
        s.save()

        # feed identical payload back in → no new revision but new meta
        current_payload = s.current_revision.get_data(self.owner)

        RevisionService.save_payload(
            secret=s,
            actor=self.owner,
            payload=copy(current_payload)
        )

        self.assertEqual(SecretRevision.objects.filter(secret=s).count(), 2)
        # Three SecretChange rows (2 payload + 1 metadata-only snapshot)
        self.assertEqual(SecretChange.objects.filter(secret=s).count(), 3)

        # History view contract: 3 rows (2 payload, 1 meta diff)
        rows = RevisionService.get_revision_history(s, self.owner)
        self.assertEqual(len(rows), 3)
