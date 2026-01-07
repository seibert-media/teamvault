from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse

from teamvault.apps.secrets.models import SecretChange
from teamvault.apps.secrets.services.revision import RevisionService
from teamvault.apps.secrets.utils import copy_meta_from_secret
from ..utils import COMMON_OVERRIDES, make_user, new_secret


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
        # Snapshot matches the secret's metadata at the time
        for k, v in copy_meta_from_secret(s).items():
            self.assertEqual(getattr(first, k), v)

        # Second payload change → new change with parent=first
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v2'})
        changes = list(SecretChange.objects.filter(secret=s).order_by('created'))
        self.assertEqual(len(changes), 2)
        second = changes[-1]
        self.assertEqual(first.id, second.parent_id)
        self.assertEqual(second.revision.secret_id, s.id)

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
        # snapshot should reflect the updated description
        self.assertEqual(last.description, 'meta-only')

    def test_restore_creates_change_with_restored_from(self):
        s = self.secret
        # Add a second payload
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v2'})
        rev1_change = SecretChange.objects.filter(
            secret=s, revision=s.secretrevision_set.order_by('created').first()
        ).latest('created')
        head_before = SecretChange.objects.filter(secret=s).latest('created')

        # Restore to first revision
        RevisionService.restore_to_change(secret=s, actor=self.owner, change=rev1_change)

        head_after = SecretChange.objects.filter(secret=s).latest('created')
        self.assertIsNotNone(head_after.restored_from)
        self.assertEqual(head_after.restored_from_id, rev1_change.id)
        # Parent points to previous head
        self.assertEqual(head_before.id, head_after.parent_id)

    def test_validation_mismatched_revision_secret(self):
        # second secret
        bob = make_user('bob')
        s1 = self.secret
        s2 = new_secret(bob)
        # Use a valid revision from s1, but try to attach to s2
        ch1 = SecretChange.objects.filter(secret=s1).latest('created')
        with self.assertRaises(ValidationError):
            SecretChange(
                secret=s2,
                revision=ch1.revision,
                actor=self.owner,
                **copy_meta_from_secret(s2),
            ).save()

    def test_change_is_immutable(self):
        s = self.secret
        other = make_user('charlie')
        ch = SecretChange.objects.filter(secret=s).latest('created')
        ch.actor = other
        with self.assertRaises(ValidationError):
            ch.save()

    def test_delete_change_scrubs_metadata_and_retains_revision(self):
        s = self.secret
        admin = make_user('admin', superuser=True)

        # Introduce a metadata-only change with sensitive description
        s.description = 'leaked-secret'
        s.save()
        payload = s.current_revision.peek_data(self.owner)
        RevisionService.save_payload(secret=s, actor=self.owner, payload=payload)
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v3'})

        changes = list(SecretChange.objects.filter(secret=s).order_by('created'))
        first, target, last = changes[0], changes[1], changes[2]
        self.assertEqual(target.description, 'leaked-secret')

        updated = RevisionService.delete_change(change=target, actor=admin)

        self.assertEqual(updated, 1)
        target_after = SecretChange.objects.get(pk=target.pk)
        self.assertEqual(target_after.description, first.description)
        self.assertEqual(target_after.name, first.name)
        self.assertEqual(target_after.parent_id, first.id)
        self.assertEqual(target_after.scrubbed_by, admin)
        self.assertIsNotNone(target_after.scrubbed_at)
        self.assertEqual(SecretChange.objects.filter(secret=s).count(), 3)

        updated_last = SecretChange.objects.get(pk=last.pk)
        self.assertEqual(updated_last.parent_id, target.pk)

        rows = RevisionService.get_revision_history(s, self.owner)
        scrub_row = next(r for r in rows if r.change_hash == target.hashid)
        self.assertTrue(any(c['label'] == 'Scrubbed' for c in scrub_row.changes))

    def test_delete_change_requires_superuser(self):
        s = self.secret
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v2'})
        target = SecretChange.objects.filter(secret=s).order_by('created')[1]
        with self.assertRaises(PermissionDenied):
            RevisionService.delete_change(change=target, actor=self.owner)

    def test_superuser_can_delete_change_via_view(self):
        s = self.secret
        admin = make_user('admin2', superuser=True)
        s.description = 'meta-leak'
        s.save()
        payload = s.current_revision.peek_data(self.owner)
        RevisionService.save_payload(secret=s, actor=self.owner, payload=payload)
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v3'})
        changes = list(SecretChange.objects.filter(secret=s).order_by('created'))
        first, target, last = changes[0], changes[1], changes[2]

        self.client.force_login(admin)
        url = reverse('secrets.secret-change-delete', kwargs={'hashid': s.hashid, 'change_hashid': target.hashid})
        response = self.client.post(url)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], reverse('secrets.secret-revisions', kwargs={'hashid': s.hashid}))
        target_after = SecretChange.objects.get(pk=target.pk)
        self.assertEqual(target_after.description, first.description)
        self.assertEqual(target_after.name, first.name)
        self.assertEqual(target_after.parent_id, first.id)
        self.assertEqual(target_after.scrubbed_by, admin)
        self.assertIsNotNone(target_after.scrubbed_at)
        updated_last = SecretChange.objects.get(pk=last.pk)
        self.assertEqual(updated_last.parent_id, target.pk)

    def test_non_superuser_cannot_delete_change_via_view(self):
        s = self.secret
        RevisionService.save_payload(secret=s, actor=self.owner, payload={'password': 'v2'})
        target = SecretChange.objects.filter(secret=s).order_by('created')[1]

        self.client.force_login(self.owner)
        url = reverse('secrets.secret-change-delete', kwargs={'hashid': s.hashid, 'change_hashid': target.hashid})
        response = self.client.post(url)

        self.assertEqual(response.status_code, 403)
        self.assertTrue(SecretChange.objects.filter(pk=target.pk).exists())
