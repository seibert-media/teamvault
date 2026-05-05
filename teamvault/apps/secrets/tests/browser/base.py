import os
import unittest
from pathlib import Path

from django.conf import settings
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.test import override_settings
from django.urls import reverse
from playwright.sync_api import Error as PlaywrightError, sync_playwright

from ..utils import COMMON_OVERRIDES, make_user, new_secret

SUPERUSER_NAME = 'e2e_admin'
SUPERUSER_PASSWORD = 'pw'  # matches make_user()


@override_settings(**COMMON_OVERRIDES)
class PlaywrightTestCase(StaticLiveServerTestCase):
    """Base class for Playwright browser smoke tests.

    Launches Chromium once per test class, opens a fresh page per test,
    and logs in as a Django superuser before each test. Captures any
    JS pageerror or console.error during navigation so subclasses can
    assert on a clean page load.
    """

    @classmethod
    def setUpClass(cls):
        # Tests must run against a real frontend bundle, otherwise inline
        # scripts that depend on jQuery / select2 will fail and report
        # false positives.
        if not (Path(settings.PROJECT_ROOT) / 'webpack-stats.json').exists():
            raise unittest.SkipTest('webpack-stats.json missing. Run `bun run build` first')

        os.environ['DJANGO_ALLOW_ASYNC_UNSAFE'] = 'true'
        super().setUpClass()
        cls.playwright = sync_playwright().start()
        # Force the full Chromium binary so the suite works whether or not
        # chrome-headless-shell was installed (we run `playwright install
        # --no-shell` in CI to keep the install footprint small).
        cls.browser = cls.playwright.chromium.launch(
            headless=True,
            executable_path=cls.playwright.chromium.executable_path,
        )

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        os.environ.pop('DJANGO_ALLOW_ASYNC_UNSAFE', None)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.superuser = make_user(SUPERUSER_NAME, superuser=True)
        self.secret = new_secret(self.superuser, name='Smoke Secret')
        self.page = self.browser.new_page()
        self.js_errors: list[str] = []
        self.page.on('pageerror', lambda exc: self.js_errors.append(f'pageerror: {exc}'))
        self.page.on('console', self._on_console)
        self.page.on('response', self._on_response)
        self._login(SUPERUSER_NAME, SUPERUSER_PASSWORD)

    def tearDown(self):
        self.page.close()
        super().tearDown()

    def _on_console(self, msg):
        if msg.type == 'error':
            url = msg.location.get('url') if msg.location else ''
            self.js_errors.append(f'console.error: {msg.text} ({url})' if url else f'console.error: {msg.text}')

    def _on_response(self, response):
        # Surface any non-success HTTP response so failures point at the
        # actual URL instead of just "Failed to load resource".
        if response.status >= 400:  # noqa: PLR2004
            self.js_errors.append(f'http {response.status}: {response.url}')

    def _login(self, username, password):
        self.page.goto(f'{self.live_server_url}{reverse("accounts.login")}')
        self.page.fill('input[name="username"]', username)
        self.page.fill('input[name="password"]', password)
        self.page.click('button[type="submit"]')
        self.page.wait_for_url(lambda url: '/login/' not in url)
        # Discard any JS errors collected during login. They are tested
        # by routing-specific smoke checks, not by the bootstrap login flow.
        self.js_errors.clear()

    def smoke(self, path: str, dom_selector: str = 'footer'):
        """Navigate to ``path`` and assert no JS errors and a known element rendered."""
        self.js_errors.clear()
        self.page.goto(f'{self.live_server_url}{path}')
        try:
            self.page.wait_for_selector(dom_selector, state='attached', timeout=5_000)
        except PlaywrightError as exc:
            raise AssertionError(f'expected element {dom_selector!r} not found on {path}: {exc}') from exc
        # Wait for HTMX hx-trigger="load" fragments and any other deferred
        # requests to settle, otherwise errors fired during async swaps
        # would slip past the assertion below.
        self.page.wait_for_load_state('networkidle')
        self.assertEqual([], self.js_errors, f'JS errors on {path}: {self.js_errors}')
