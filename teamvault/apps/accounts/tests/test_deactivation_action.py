from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test.testcases import TestCase
from django.urls import reverse

from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
from teamvault.apps.secrets.models import Secret, SecretRevision


class TestUserDeactivationSideEffects(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(
            username='admin',
            password='<PASSWORD>',
            is_superuser=True,
            is_staff=True,
        )

        self.bob = User.objects.create_user(
            username='bob',
            password='<PASSWORD>',
            is_active=True,
        )

        self.dev_group = Group.objects.create(name='Developers')
        self.bob.groups.add(self.dev_group)

    def _create_secret_and_simulate_access(self, name, user_accessed=False, on_leave=True):
        secret = Secret.objects.create(
            name=name,
            created_by=self.admin,
            status=SecretStatus.OK,
            needs_changing_on_leave=on_leave,
            access_policy=AccessPolicy.ANY,
        )

        revision = SecretRevision.objects.create(
            secret=secret, set_by=self.admin, plaintext_data_sha256=f'hash_{name}', encrypted_data=b'fake'
        )
        secret.current_revision = revision
        secret.save()

        if user_accessed:
            revision.accessed_by.add(self.bob)

        return secret

    def test_deactivation_marks_accessed_secrets_as_needs_changing(self):
        secret = self._create_secret_and_simulate_access('secret', user_accessed=True)
        self.client.force_login(self.admin)
        url = reverse('accounts.user-deactivate', kwargs={'username': self.bob.username})
        self.client.post(url)

        secret.refresh_from_db()
        self.assertEqual(secret.status, SecretStatus.NEEDS_CHANGING)

    def test_deactivation_ignores_unaccessed_secrets(self):
        secret = self._create_secret_and_simulate_access('secret', user_accessed=False, on_leave=True)
        self.client.force_login(self.admin)
        url = reverse('accounts.user-deactivate', kwargs={'username': self.bob.username})
        self.client.post(url)
        secret.refresh_from_db()
        self.assertEqual(secret.status, SecretStatus.OK)

    def test_deactivation_removes_group_membership(self):
        self.client.force_login(self.admin)
        url = reverse('accounts.user-deactivate', kwargs={'username': self.bob.username})
        self.client.post(url)

        self.bob.refresh_from_db()

        self.assertFalse(self.bob.is_active)
        self.assertEqual(self.bob.groups.count(), 0)

    def test_reactivation_does_not_fix_secrets(self):
        secret = self._create_secret_and_simulate_access('secret', user_accessed=True)
        self.client.force_login(self.admin)
        url = reverse('accounts.user-deactivate', kwargs={'username': self.bob.username})
        self.client.post(url)
        secret.refresh_from_db()
        self.assertEqual(secret.status, SecretStatus.NEEDS_CHANGING)

        self.client.post(reverse('accounts.user-reactivate', kwargs={'username': self.bob.username}))
        secret.refresh_from_db()

        self.assertEqual(secret.status, SecretStatus.NEEDS_CHANGING)

    def test_deactivation_ignores_safe_secrets(self):
        """
        If needs_changing_on_leave=False,
        deactivation should NOT flag the secret, even if accessed.
        """
        secret = self._create_secret_and_simulate_access('Wifi Password', user_accessed=True, on_leave=False)

        self.client.force_login(self.admin)
        url = reverse('accounts.user-deactivate', kwargs={'username': self.bob.username})
        self.client.post(url)
        secret.refresh_from_db()

        self.assertEqual(secret.status, SecretStatus.OK)
