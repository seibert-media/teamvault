from django.test import TestCase, override_settings
from django.urls import reverse

from teamvault.apps.secrets.enums import AccessPolicy, SecretStatus
from teamvault.apps.secrets.models import Secret
from ..utils import COMMON_OVERRIDES, make_user, new_secret


def _detail_url(secret: Secret) -> str:
    return reverse("secrets.secret-detail", kwargs={"hashid": secret.hashid})


def _delete_url(secret: Secret) -> str:
    return reverse("secrets.secret-delete", kwargs={"hashid": secret.hashid})


def _restore_url(secret: Secret) -> str:
    return reverse("secrets.secret-restore", kwargs={"hashid": secret.hashid})


def _share_url(secret: Secret) -> str:
    return reverse("secrets.secret-share", kwargs={"hashid": secret.hashid})


def _edit_url(secret: Secret) -> str:
    return reverse("secrets.secret-edit", kwargs={"hashid": secret.hashid})


@override_settings(**COMMON_OVERRIDES)
class SecretCrudViewTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user("owner")
        cls.bob = make_user("bob")
        cls.su = make_user("root", superuser=True)
        cls.secret: Secret = new_secret(cls.owner, name="view-crud")

    def test_detail_visible_for_owner(self):
        self.client.force_login(self.owner)
        resp = self.client.get(_detail_url(self.secret))
        self.assertEqual(resp.status_code, 200)

    def test_detail_visible_for_non_owner_discoverable(self):
        """DISCOVERABLE makes it listable/visible but not necessarily readable."""
        self.client.force_login(self.bob)
        resp = self.client.get(_detail_url(self.secret))
        self.assertEqual(resp.status_code, 200)

    def test_owner_can_delete(self):
        self.client.force_login(self.owner)
        resp = self.client.post(_delete_url(self.secret))
        self.assertIn(resp.status_code, (302, 303))

        self.secret.refresh_from_db()
        self.assertEqual(self.secret.status, SecretStatus.DELETED)

    def test_non_owner_cannot_delete(self):
        """Non-owner has visibility (discoverable) but not read permission → 403."""
        self.client.force_login(self.bob)
        resp = self.client.post(_delete_url(self.secret))
        self.assertEqual(resp.status_code, 403)

    def test_restore_requires_superuser(self):
        """
        Behavior:
        - Non-superuser hits @user_passes_test → 302 redirect to login.
        - Superuser can view the restore page and restore deleted secrets.
        """
        self.client.force_login(self.owner)
        self.client.post(_delete_url(self.secret))
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.status, SecretStatus.DELETED)

        # Non-superuser attempt → redirect to login (302)
        self.client.force_login(self.bob)
        resp_non_su = self.client.post(_restore_url(self.secret))
        self.assertEqual(resp_non_su.status_code, 302)

        # Superuser can view and restore
        self.client.force_login(self.su)
        resp_su_get = self.client.get(_restore_url(self.secret))
        self.assertEqual(resp_su_get.status_code, 200)

        resp_su_post = self.client.post(_restore_url(self.secret))
        self.assertIn(resp_su_post.status_code, (302, 303))
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.status, SecretStatus.OK)

    def test_share_list_modal_forbidden_for_user_without_share_rights(self):
        """
        DISCOVERABLE secret is visible to bob but not shareable; view calls
        check_share_access() which raises PermissionDenied → 403.
        """
        self.client.force_login(self.bob)
        resp = self.client.get(_share_url(self.secret))
        self.assertEqual(resp.status_code, 403)

    def test_share_list_modal_ok_for_owner(self):
        self.client.force_login(self.owner)
        resp = self.client.get(_share_url(self.secret))
        self.assertEqual(resp.status_code, 200)

    def test_edit_forbidden_without_read_access(self):
        """
        For DISCOVERABLE + no share, check_read_access raises PermissionDenied → 403.
        """
        self.client.force_login(self.bob)
        resp = self.client.get(_edit_url(self.secret))
        self.assertEqual(resp.status_code, 403)

    def test_deleted_secret_detail_is_404(self):
        self.client.force_login(self.owner)
        self.client.post(_delete_url(self.secret))
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.status, SecretStatus.DELETED)

        # Deleted secrets stay hidden for regular users but are visible to superusers.
        for u in (self.owner, self.bob):
            self.client.force_login(u)
            resp = self.client.get(_detail_url(self.secret))
            self.assertEqual(resp.status_code, 404)

        self.client.force_login(self.su)
        resp_su = self.client.get(_detail_url(self.secret))
        self.assertEqual(resp_su.status_code, 200)


    def test_access_policy_any_makes_detail_readable_for_everyone(self):
        self.secret.access_policy = AccessPolicy.ANY
        self.secret.save(update_fields=["access_policy"])

        self.client.force_login(self.bob)
        resp = self.client.get(_detail_url(self.secret))
        self.assertEqual(resp.status_code, 200)
