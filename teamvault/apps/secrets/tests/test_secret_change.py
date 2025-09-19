from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings

from teamvault.apps.secrets.models import SecretChange, SecretChangeParent
from teamvault.apps.secrets.services.revision import RevisionService
from .utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class SecretChangeTests(TestCase):
    def setUp(self):
        self.owner = make_user('alice')
        self.secret = new_secret(self.owner)

    def test_change_created_on_save_payload(self):
        s = self.secret
        # After initial creation
        changes = list(SecretChange.objects.filter(secret=s).order_by('created'))
        self.assertEqual(len(changes), 1)
        first = changes[0]
        self.assertEqual(first.revision.secret_id, s.id)
        self.assertEqual(first.metadata.revision_id, first.revision_id)

        # Second payload change → new change with parent=first
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v2'})
        changes = list(SecretChange.objects.filter(secret=s).order_by('created'))
        self.assertEqual(len(changes), 2)
        second = changes[-1]
        self.assertIn(first, second.parents.all())
        self.assertEqual(second.revision.secret_id, s.id)
        self.assertEqual(second.metadata.revision_id, second.revision_id)

    def test_metadata_only_creates_change(self):
        s = self.secret
        start_changes = SecretChange.objects.filter(secret=s).count()
        # Change metadata but keep payload identical
        s.description = 'meta-only'
        s.save()
        payload = s.current_revision.peek_data(self.owner)
        RevisionService.save_payload(secret=s, actor=self.owner, payload=payload)
        changes = list(SecretChange.objects.filter(secret=s).order_by('created'))
        self.assertEqual(len(changes), start_changes + 1)
        last = changes[-1]
        # payload unchanged → same revision id as before
        self.assertEqual(last.revision_id, s.current_revision_id)
        # metadata must point to that revision
        self.assertEqual(last.metadata.revision_id, last.revision_id)

    def test_restore_creates_change_with_restored_from(self):
        s = self.secret
        # Add a second payload
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v2'})
        rev1_change = SecretChange.objects.filter(secret=s, revision=s.secretrevision_set.order_by('created').first()).latest('created')
        head_before = SecretChange.objects.filter(secret=s).latest('created')

        # Restore to first revision
        rev1 = s.secretrevision_set.order_by('created').first()
        RevisionService.restore(secret=s, actor=self.owner, old_revision=rev1)

        head_after = SecretChange.objects.filter(secret=s).latest('created')
        self.assertIsNotNone(head_after.restored_from)
        self.assertEqual(head_after.restored_from_id, rev1_change.id)
        # Parent points to previous head
        self.assertIn(head_before, head_after.parents.all())

    def test_validation_mismatched_revision_secret(self):
        # second secret
        bob = make_user('bob')
        s1 = self.secret
        s2 = new_secret(bob)
        # Use a valid metadata+revision from s1, but try to attach to s2
        ch1 = SecretChange.objects.filter(secret=s1).latest('created')
        with self.assertRaises(ValidationError):
            SecretChange(
                secret=s2,
                revision=ch1.revision,
                metadata=ch1.metadata,
                actor=self.owner,
            ).save()

    def test_validation_mismatched_metadata_revision(self):
        s = self.secret
        # Create a second payload so we have metadata on two different revisions
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v2'})
        r1 = s.secretrevision_set.order_by('created').first()
        r2 = s.secretrevision_set.order_by('created').last()
        meta_r2 = r2.metas.latest('created')
        with self.assertRaises(ValidationError):
            SecretChange(
                secret=s,
                revision=r1,
                metadata=meta_r2,
                actor=self.owner,
            ).save()

    def test_parent_through_constraints(self):
        s = self.secret
        # Add one more change
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v2'})
        first = SecretChange.objects.filter(secret=s).order_by('created').first()
        second = SecretChange.objects.filter(secret=s).order_by('created').last()
        # Duplicate parent edge (edge already exists from service layer)
        with self.assertRaises(IntegrityError), transaction.atomic():
            SecretChangeParent.objects.create(parent=first, child=second)
        # Self edge forbidden
        with self.assertRaises(IntegrityError), transaction.atomic():
            SecretChangeParent.objects.create(parent=second, child=second)

    def test_change_is_immutable(self):
        s = self.secret
        other = make_user('charlie')
        ch = SecretChange.objects.filter(secret=s).latest('created')
        ch.actor = other
        with self.assertRaises(ValidationError):
            ch.save()
