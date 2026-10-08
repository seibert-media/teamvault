from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.forms import PasswordForm
from teamvault.apps.secrets.models import SharedSecretData
from ..utils import COMMON_OVERRIDES, make_user, new_secret


def _share_url(secret) -> str:
    return reverse('secrets.secret-share', kwargs={'hashid': secret.hashid})


def _api_share_url(secret) -> str:
    return reverse('api.secret_share', args=[secret.hashid])


def _create_form_with_group_share(grant_description: str) -> PasswordForm:
    group = Group.objects.create(name='reason-group')
    return PasswordForm(
        data={
            'name': 'new secret',
            'access_policy': AccessPolicy.DISCOVERABLE,
            'password': 'pw',
            'shared_groups_on_create': [group.pk],
            'grant_description': grant_description,
        }
    )


@override_settings(**COMMON_OVERRIDES)
class ShareReasonRequirementTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.target = make_user('target')
        self.secret = new_secret(self.owner, name='reason-secret', access_policy=AccessPolicy.HIDDEN)

    def _share_via_view(self, grant_description: str):
        self.client.force_login(self.owner)
        return self.client.post(
            _share_url(self.secret),
            data={'user': self.target.pk, 'grant_description': grant_description, 'granted_until': ''},
        )

    def _share_via_api(self, grant_description: str):
        api_client = APIClient()
        api_client.force_authenticate(user=self.owner)
        return api_client.post(
            _api_share_url(self.secret),
            data={
                'user': self.target.username,
                'group': None,
                'grant_description': grant_description,
                'granted_until': None,
            },
            format='json',
        )

    @override_settings(REQUIRE_SHARE_REASON=True)
    def test_view_rejects_share_without_reason_when_required(self):
        response = self._share_via_view('')

        self.assertFalse(SharedSecretData.objects.filter(secret=self.secret, user=self.target).exists())
        self.assertIn('grant_description', response.context['form'].errors)

    @override_settings(REQUIRE_SHARE_REASON=False)
    def test_view_accepts_share_without_reason_when_not_required(self):
        response = self._share_via_view('')

        self.assertEqual(response.status_code, 200)
        self.assertTrue(SharedSecretData.objects.filter(secret=self.secret, user=self.target).exists())

    @override_settings(REQUIRE_SHARE_REASON=True)
    def test_api_rejects_share_without_reason_when_required(self):
        response = self._share_via_api('')

        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn('grant_description', response.data)

    @override_settings(REQUIRE_SHARE_REASON=False)
    def test_api_accepts_share_without_reason_when_not_required(self):
        response = self._share_via_api('')

        self.assertEqual(response.status_code, 201, response.data)
        self.assertTrue(SharedSecretData.objects.filter(secret=self.secret, user=self.target).exists())

    @override_settings(REQUIRE_SHARE_REASON=True)
    def test_create_form_rejects_initial_group_share_without_reason_when_required(self):
        form = _create_form_with_group_share('')

        self.assertFalse(form.is_valid())
        self.assertIn('grant_description', form.errors)

    @override_settings(REQUIRE_SHARE_REASON=False)
    def test_create_form_accepts_initial_group_share_without_reason_when_not_required(self):
        form = _create_form_with_group_share('')

        self.assertTrue(form.is_valid(), form.errors)
