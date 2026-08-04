from django.test import Client, TestCase


class AnonymousDocsTest(TestCase):
    """The API docs are a public contract: no auth on the viewer or the schema."""

    def test_openapi_json_is_public(self):
        response = Client().get('/api/v2/openapi.json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['info']['title'], 'TeamVault API')

    def test_docs_ui_is_public(self):
        response = Client().get('/api/v2/docs')
        self.assertEqual(response.status_code, 200)

    def test_docs_ui_renders_stoplight_elements_from_vendored_bundle(self):
        content = Client().get('/api/v2/docs').content.decode()
        self.assertIn('<elements-api', content)
        self.assertIn('/static/bundled/stoplight-elements.min.js', content)
        self.assertIn('/static/bundled/stoplight-elements.min.css', content)
        self.assertIn('/api/v2/openapi.json', content)
        # The docs page must not load anything from a CDN.
        self.assertNotIn('cdn.', content)
        self.assertNotIn('unpkg', content)
