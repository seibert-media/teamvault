from django.test import TestCase
from django.contrib.auth import get_user_model

from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
from teamvault.apps.secrets.models import Secret, SharedSecretData
from teamvault.apps.accounts.utils import get_pending_secrets_for_user


class TestPendingSecretsQueryLogic(TestCase):
    def setUp(self):
        User = get_user_model()
        self.bob = User.objects.create_user(username="bob", password="x")
        self.alice = User.objects.create_user(username="alice", password="x")

    def test_query_filters_correctly(self):
        self.bob.is_active = False
        self.bob.save()

        global_needs_change = Secret.objects.create(
            name="global_needs_change",
            created_by=self.alice,
            access_policy=AccessPolicy.ANY,
            status=SecretStatus.NEEDS_CHANGING,
            needs_changing_on_leave=True,
        )

        global_needs_change_but_not_on_leave = Secret.objects.create(
            name="global_needs_change_not_on_leave",
            created_by=self.alice,
            access_policy=AccessPolicy.ANY,
            status=SecretStatus.NEEDS_CHANGING,
            needs_changing_on_leave=False,
        )

        shared_secret = Secret.objects.create(
            name="shared_needs_change",
            created_by=self.alice,
            access_policy=AccessPolicy.HIDDEN,
            status=SecretStatus.NEEDS_CHANGING,
            needs_changing_on_leave=True,
        )
        SharedSecretData.objects.create(
            secret=shared_secret,
            user=self.bob,
            granted_by=self.alice,
        )

        hidden_for_alice_only = Secret.objects.create(
            name="hidden_for_alice_only",
            created_by=self.alice,
            access_policy=AccessPolicy.HIDDEN,
            status=SecretStatus.NEEDS_CHANGING,
            needs_changing_on_leave=True,
        )
        SharedSecretData.objects.create(
            secret=hidden_for_alice_only,
            user=self.alice,
            granted_by=self.alice,
        )

        deleted_needs_change = Secret.objects.create(
            name="deleted_needs_change",
            created_by=self.alice,
            access_policy=AccessPolicy.ANY,
            status=SecretStatus.DELETED,
            needs_changing_on_leave=True,
        )

        pending = list(get_pending_secrets_for_user(self.bob))

        self.assertEqual(
            pending,
            [global_needs_change, shared_secret],
        )

