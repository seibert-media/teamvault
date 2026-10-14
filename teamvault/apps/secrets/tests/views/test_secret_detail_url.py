from django.test import TestCase, override_settings
from django.urls import reverse

from ..utils import COMMON_OVERRIDES, make_user, new_secret


@override_settings(**COMMON_OVERRIDES)
class SecretDetailUrlRenderingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')

    def _detail_html(self, url):
        secret = new_secret(self.owner)
        secret.url = url
        secret.save()
        self.client.force_login(self.owner)
        resp = self.client.get(reverse('secrets.secret-detail', args=[secret.hashid]))
        self.assertEqual(resp.status_code, 200)
        return resp.content.decode()

    def test_http_url_is_rendered_as_link(self):
        html = self._detail_html('https://example.com/login')
        self.assertIn('href="https://example.com/login"', html)

    def test_script_url_is_rendered_as_text_only(self):
        html = self._detail_html('JavaScript://%0Aalert(1)')
        self.assertNotIn('href="JavaScript', html)
        self.assertNotIn('href="javascript', html)
        self.assertIn('JavaScript://%0Aalert(1)', html)
