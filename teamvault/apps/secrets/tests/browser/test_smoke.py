from django.urls import reverse

from teamvault.apps.secrets.enums import ContentType
from .base import PlaywrightTestCase
from ..utils import new_secret


class SmokeTests(PlaywrightTestCase):
    """Loads each major authenticated page and asserts no JS errors fire.

    Catches the class of bug where inline ``<script>`` blocks in templates
    produce invalid JS at render time (e.g. unquoted translation tags).
    Backend tests don't run JS, so these failures only surface in a browser.
    """

    def test_dashboard(self):
        self.smoke(reverse('dashboard'))

    def test_secret_list(self):
        # Originating page from the bug this suite was built to catch.
        self.smoke(reverse('secrets.secret-list'), dom_selector='#filter-modal')

    def test_secret_detail(self):
        self.smoke(reverse('secrets.secret-detail', kwargs={'hashid': self.secret.hashid}))

    def test_secret_detail_cc(self):
        cc = new_secret(self.superuser, content_type=ContentType.CC, name='Smoke CC')
        self.smoke(reverse('secrets.secret-detail', kwargs={'hashid': cc.hashid}))

    def test_secret_detail_file(self):
        f = new_secret(self.superuser, content_type=ContentType.FILE, name='Smoke File')
        self.smoke(reverse('secrets.secret-detail', kwargs={'hashid': f.hashid}))

    def test_secret_edit(self):
        self.smoke(reverse('secrets.secret-edit', kwargs={'hashid': self.secret.hashid}))

    def test_secret_add_password(self):
        self.smoke(reverse('secrets.secret-add', kwargs={'content_type': 'password'}))

    def test_secret_add_cc(self):
        self.smoke(reverse('secrets.secret-add', kwargs={'content_type': 'cc'}))

    def test_secret_add_file(self):
        self.smoke(reverse('secrets.secret-add', kwargs={'content_type': 'file'}))

    def test_user_list(self):
        self.smoke(reverse('accounts.user-list'))

    def test_user_settings(self):
        self.smoke(reverse('accounts.user-settings'))

    def test_audit_log(self):
        self.smoke(reverse('audit.log'), dom_selector='#filter-modal')
