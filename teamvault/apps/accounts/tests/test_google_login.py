from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.test import TestCase, override_settings
from django.urls import reverse
from django_test_migrations.contrib.unittest_case import MigratorTestCase
from social_django.models import UserSocialAuth

from teamvault.apps.accounts.backends import UUIDLinkingLDAPBackend
from teamvault.apps.settings.config import google_auth_pipeline

User = get_user_model()

GOOGLE_PROFILE = {
    'sub': '108204268033311374519',
    'email': 'alice@example.com',
    'email_verified': True,
    'name': 'Alice Example',
    'given_name': 'Alice',
    'family_name': 'Example',
}

google_auth_settings = override_settings(
    AUTHENTICATION_BACKENDS=[
        'social_core.backends.google.GoogleOAuth2',
        'django.contrib.auth.backends.ModelBackend',
    ],
    SOCIAL_AUTH_GOOGLE_OAUTH2_KEY='test-key',
    SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET='test-secret',
    SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS=['example.com'],
    SOCIAL_AUTH_RAISE_EXCEPTIONS=False,
)


class GoogleLoginTestCase(TestCase):
    def login_with_google(self, profile=GOOGLE_PROFILE):
        begin = self.client.post(reverse('social:begin', args=['google-oauth2']))
        self.assertEqual(begin.status_code, 302)
        state = parse_qs(urlparse(begin['Location']).query)['state'][0]

        def google_api(_method, url, **_kwargs):
            payload = profile if 'userinfo' in url else {'access_token': 'token', 'token_type': 'Bearer'}
            return Mock(status_code=200, json=Mock(return_value=payload))

        with patch('social_core.backends.base.requests.request', side_effect=google_api):
            return self.client.get(
                reverse('social:complete', args=['google-oauth2']),
                {'code': 'authorization-code', 'state': state},
            )

    def assertLoggedInAs(self, user):
        self.assertEqual(self.client.session.get('_auth_user_id'), str(user.pk))

    def assertRejected(self, response):
        self.assertRedirects(response, reverse('accounts.login'), fetch_redirect_response=False)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertEqual(len(get_messages(response.wsgi_request)), 1)


@google_auth_settings
@override_settings(SOCIAL_AUTH_PIPELINE=google_auth_pipeline(ldap_enabled=False, use_avatars=True))
class GoogleLoginWithoutLdapTests(GoogleLoginTestCase):
    def test_first_login_creates_user_and_association(self):
        response = self.login_with_google()

        self.assertRedirects(response, '/', fetch_redirect_response=False)
        user = User.objects.get(email='alice@example.com')
        self.assertLoggedInAs(user)
        self.assertEqual((user.username, user.first_name, user.last_name), ('alice', 'Alice', 'Example'))
        association = UserSocialAuth.objects.get(user=user)
        self.assertEqual(
            (association.provider, association.uid, association.id_key),
            ('google-oauth2', GOOGLE_PROFILE['sub'], 'sub'),
        )

    def test_returning_user_is_found_by_association(self):
        user = User.objects.create_user(username='renamed', email='old-address@example.com')
        UserSocialAuth.objects.create(user=user, provider='google-oauth2', uid=GOOGLE_PROFILE['sub'], id_key='sub')

        self.login_with_google()

        self.assertLoggedInAs(user)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(UserSocialAuth.objects.count(), 1)

    def test_existing_user_is_matched_by_email(self):
        user = User.objects.create_user(username='local-alice', email='alice@example.com')

        self.login_with_google()

        self.assertLoggedInAs(user)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(UserSocialAuth.objects.get().user, user)

    def test_domain_outside_allow_list_is_rejected(self):
        response = self.login_with_google({**GOOGLE_PROFILE, 'email': 'alice@elsewhere.test'})

        self.assertRejected(response)
        self.assertFalse(User.objects.exists())

    def test_unverified_email_is_rejected(self):
        response = self.login_with_google({**GOOGLE_PROFILE, 'email_verified': False})

        self.assertRejected(response)
        self.assertFalse(User.objects.exists())


@google_auth_settings
@override_settings(SOCIAL_AUTH_PIPELINE=google_auth_pipeline(ldap_enabled=True, use_avatars=True))
class GoogleLoginWithLdapTests(GoogleLoginTestCase):
    def setUp(self):
        self.search_by_mail = self.enterContext(patch('teamvault.apps.accounts.backends.search_by_mail'))
        self.search_by_ldap_uuid = self.enterContext(patch('teamvault.apps.accounts.backends.search_by_ldap_uuid'))
        self.populate_user = self.enterContext(patch.object(UUIDLinkingLDAPBackend, 'populate_user'))

    def test_first_login_links_the_ldap_user_found_by_email(self):
        user = User.objects.create_user(username='alice', email='alice@example.com')
        self.search_by_mail.return_value = [('uid=alice,dc=example', {'uid': [b'alice']})]
        self.populate_user.return_value = user

        self.login_with_google()

        self.search_by_mail.assert_called_once_with('alice@example.com')
        self.populate_user.assert_called_once_with('alice')
        self.assertLoggedInAs(user)
        self.assertEqual(UserSocialAuth.objects.get().user, user)

    def test_returning_user_is_refreshed_by_ldap_uuid(self):
        user = User.objects.create_user(username='alice', email='alice@example.com', ldap_uuid='ldap-uuid-1')
        UserSocialAuth.objects.create(user=user, provider='google-oauth2', uid=GOOGLE_PROFILE['sub'], id_key='sub')
        self.search_by_ldap_uuid.return_value = [('uid=alice,dc=example', {'uid': ['alice']})]
        self.populate_user.return_value = user

        self.login_with_google()

        self.search_by_ldap_uuid.assert_called_once_with('ldap-uuid-1')
        self.search_by_mail.assert_not_called()
        self.assertLoggedInAs(user)
        self.assertEqual(UserSocialAuth.objects.count(), 1)

    def test_user_missing_in_ldap_is_rejected(self):
        self.search_by_mail.return_value = []

        response = self.login_with_google()

        self.assertRejected(response)
        self.populate_user.assert_not_called()
        self.assertFalse(User.objects.exists())

    def test_returning_user_removed_from_ldap_is_rejected(self):
        user = User.objects.create_user(username='alice', email='alice@example.com', ldap_uuid='ldap-uuid-1')
        UserSocialAuth.objects.create(user=user, provider='google-oauth2', uid=GOOGLE_PROFILE['sub'], id_key='sub')
        self.search_by_ldap_uuid.return_value = []

        response = self.login_with_google()

        self.assertRejected(response)


class GoogleAssociationIdKeyBackfillTest(MigratorTestCase):
    migrate_from = ('social_django', '0017_usersocialauth_user_social_auth_uid_required')
    migrate_to = ('social_django', '0022_nonce_timestamp_index')

    def prepare(self):
        user = self.old_state.apps.get_model('accounts', 'User').objects.create(username='alice')
        self.old_state.apps.get_model('social_django', 'UserSocialAuth').objects.create(
            user=user,
            provider='google-oauth2',
            uid=GOOGLE_PROFILE['sub'],
        )

    def test_existing_google_associations_are_keyed_by_sub(self):
        association = self.new_state.apps.get_model('social_django', 'UserSocialAuth').objects.get()
        self.assertEqual(association.id_key, 'sub')
