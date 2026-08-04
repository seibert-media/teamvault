"""v1 (legacy DRF) deprecation headers + served MIGRATION.md.

Per RFC 8594, every v1 response must carry a `Deprecation` header and a `Link` header pointing
at the migration guide. The header test enumerates the v1 URLconf so newly added v1 routes are
covered automatically; the negative case (v2 must stay clean) is tested separately.
"""

from django.test import Client, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from teamvault.apps.secrets.api import urls as v1_urls
from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.services.revision import RevisionService
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user, new_secret

# Deliberately a literal (not imported from teamvault.middleware): the header value is an API
# contract, so this test must fail if the production constant changes.
DEPRECATION_LINK = '</api/v2/MIGRATION.md>; rel="deprecation"'


@override_settings(**COMMON_OVERRIDES)
class V1DeprecationHeaderTests(TestCase):
    def setUp(self):
        self.user = make_user('alice', superuser=True)
        self.secret = new_secret(self.user, name='dep-secret', access_policy=AccessPolicy.ANY)
        # An OTP-capable payload so the v1 OTP route responds instead of erroring.
        RevisionService.save_payload(
            secret=self.secret,
            actor=self.user,
            payload={'otp_key': 'JBSWY3DPEHPK3PXP', 'digits': '6', 'algorithm': 'SHA1'},
        )
        self.secret.refresh_from_db()
        self.revision = self.secret.current_revision
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def _v1_urls(self):
        """Reverse every pattern in the v1 URLconf (the middleware must tag them all)."""
        urls = []
        for pattern in v1_urls.urlpatterns:
            route = str(pattern.pattern)
            kwargs = {}
            if '<str:username>' in route:
                kwargs['username'] = self.user.username
            if '<str:hashid>' in route:
                is_revision_route = route.startswith('secret-revisions')
                kwargs['hashid'] = self.revision.hashid if is_revision_route else self.secret.hashid
            if '<int:pk>' in route:
                # The creator is auto-shared on create, so the secret always has one share row.
                kwargs['pk'] = self.secret.share_data.first().pk
            urls.append(reverse(pattern.name, kwargs=kwargs))
        return urls

    def test_every_v1_endpoint_carries_both_headers(self):
        for url in self._v1_urls():
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.headers.get('Deprecation'), 'true', f'missing Deprecation on {url}')
                self.assertEqual(response.headers.get('Link'), DEPRECATION_LINK, f'missing Link on {url}')

    def test_headers_present_even_on_error_responses(self):
        # An unauthenticated v1 request still gets the deprecation headers.
        anon = APIClient()
        response = anon.get(reverse('api.secret_list'))
        self.assertEqual(response.headers.get('Deprecation'), 'true')
        self.assertEqual(response.headers.get('Link'), DEPRECATION_LINK)

    def test_v2_responses_are_not_marked_deprecated(self):
        response = Client().get('/api/v2/openapi.json')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Deprecation', response.headers)


@override_settings(**COMMON_OVERRIDES)
class MigrationGuideServingTests(TestCase):
    """The Link header target must resolve to the served MIGRATION.md."""

    def test_migration_md_is_served_as_markdown(self):
        response = Client().get('/api/v2/MIGRATION.md')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/markdown', response.headers['Content-Type'])

    def test_migration_md_is_public(self):
        # The guide is documentation; no auth required (matches the docs being public).
        response = Client().get('/api/v2/MIGRATION.md')
        self.assertEqual(response.status_code, 200)

    def test_migration_md_has_no_removal_date(self):
        content = Client().get('/api/v2/MIGRATION.md').content.decode().lower()
        for phrase in ('removal date', 'will be removed', 'sunset', 'end of life', 'will be shut down'):
            self.assertNotIn(phrase, content, f'MIGRATION.md must not announce removal: found {phrase!r}')
