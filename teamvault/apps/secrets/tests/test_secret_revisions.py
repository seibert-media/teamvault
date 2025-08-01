from copy import copy

from django.test import TestCase, override_settings

from teamvault.apps.secrets.models import (
    SecretMetaSnapshot,
    SecretRevision,
)
from teamvault.apps.secrets.services.revision import RevisionService
from .utils import COMMON_OVERRIDES, make_user, new_secret


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
        self.assertEqual(
            SecretMetaSnapshot.objects.filter(revision__secret=s).count(),
            1,  # baseline only
        )

        # 3rd change: ONLY metadata update
        s.description = 'New description'
        s.save()

        # feed identical payload back in → no new revision but new snapshot
        current_payload = s.current_revision.get_data(self.owner)

        RevisionService.save_payload(
            secret=s,
            actor=self.owner,
            payload=copy(current_payload)
        )

        self.assertEqual(
            SecretRevision.objects.filter(secret=s).count(),
            2,  # still two distinct payloads
        )
        self.assertEqual(
            SecretMetaSnapshot.objects.filter(revision__secret=s).count(),
            2,  # baseline + meta‑change
        )

        # History view contract: 3 “rows” (2 payload, 1 meta diff)
        payload_revs = SecretRevision.objects.filter(secret=s).count()
        meta_diffs = SecretMetaSnapshot.objects.filter(revision__secret=s).count() - 1
        self.assertEqual(payload_revs + meta_diffs, 3)
