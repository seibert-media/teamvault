from datetime import timedelta

from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.audit.models import AuditLogCategoryChoices, LogEntry
from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import SharedSecretData
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user, new_secret


def auth_header(token_string):
    return {'HTTP_AUTHORIZATION': f'Bearer {token_string}'}


def _list_url(secret) -> str:
    return f'/api/v2/secrets/{secret.hashid}/shares'


def _detail_url(secret, share_id) -> str:
    return f'/api/v2/secrets/{secret.hashid}/shares/{share_id}'


def _share_for_username(results, username):
    return next(item for item in results if item['user'] and item['user']['username'] == username)


@override_settings(**COMMON_OVERRIDES)
class ShareListTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.target = make_user('target')
        from django.contrib.auth.models import Group

        cls.group = Group.objects.create(name='ops')
        cls.secret = new_secret(cls.owner, access_policy=AccessPolicy.HIDDEN, name='shared-secret')
        _, cls.token = ApiToken.issue(user=cls.owner, name='reader', scopes=['secrets:read'])

    def _get(self, path, token=None):
        return self.client.get(path, **auth_header(token or self.token))

    def test_list_returns_user_and_group_shares(self):
        SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        SharedSecretData.objects.create(secret=self.secret, group=self.group, granted_by=self.owner)

        response = self._get(_list_url(self.secret))
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        # owner's own permanent self-share from new_secret() + the two created here
        usernames = {item['user']['username'] for item in body['results'] if item['user']}
        groups = {item['group']['name'] for item in body['results'] if item['group']}
        self.assertIn('target', usernames)
        self.assertIn('ops', groups)

    def test_is_expired_computed(self):
        SharedSecretData.objects.create(
            secret=self.secret,
            user=self.target,
            granted_by=self.owner,
            granted_until=now() - timedelta(days=1),
        )
        response = self._get(_list_url(self.secret))
        self.assertEqual(response.status_code, 200, response.content)
        share = _share_for_username(response.json()['results'], 'target')
        self.assertTrue(share['is_expired'])

    def test_active_share_not_expired(self):
        SharedSecretData.objects.create(
            secret=self.secret,
            user=self.target,
            granted_by=self.owner,
            granted_until=now() + timedelta(days=1),
        )
        response = self._get(_list_url(self.secret))
        share = _share_for_username(response.json()['results'], 'target')
        self.assertFalse(share['is_expired'])

    def test_expires_at_returned(self):
        until = now() + timedelta(days=7)
        SharedSecretData.objects.create(
            secret=self.secret, user=self.target, granted_by=self.owner, granted_until=until
        )
        response = self._get(_list_url(self.secret))
        share = _share_for_username(response.json()['results'], 'target')
        self.assertIsNotNone(share['expires_at'])
        self.assertIsNotNone(share['granted_at'])
        self.assertEqual(share['granted_by']['username'], 'owner')

    def test_filter_by_user(self):
        SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        SharedSecretData.objects.create(secret=self.secret, group=self.group, granted_by=self.owner)
        response = self._get(f'{_list_url(self.secret)}?user={self.target.pk}')
        self.assertEqual(response.status_code, 200, response.content)
        results = response.json()['results']
        self.assertTrue(all(item['user'] and item['user']['id'] == self.target.pk for item in results))

    def test_filter_by_group(self):
        SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        SharedSecretData.objects.create(secret=self.secret, group=self.group, granted_by=self.owner)
        response = self._get(f'{_list_url(self.secret)}?group={self.group.pk}')
        results = response.json()['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['group']['id'], self.group.pk)

    def test_filter_by_is_expired(self):
        SharedSecretData.objects.create(
            secret=self.secret, user=self.target, granted_by=self.owner, granted_until=now() - timedelta(days=1)
        )
        response = self._get(f'{_list_url(self.secret)}?is_expired=true')
        results = response.json()['results']
        self.assertTrue(all(item['is_expired'] for item in results))
        self.assertTrue(any(item['user'] and item['user']['username'] == 'target' for item in results))

    def test_sort_default_granted_at_desc(self):
        SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        SharedSecretData.objects.create(secret=self.secret, group=self.group, granted_by=self.owner)
        response = self._get(_list_url(self.secret))
        granted = [item['granted_at'] for item in response.json()['results']]
        self.assertEqual(granted, sorted(granted, reverse=True))

    def test_expand_user_group_granted_by(self):
        SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        SharedSecretData.objects.create(secret=self.secret, group=self.group, granted_by=self.owner)
        response = self._get(f'{_list_url(self.secret)}?expand=user,group,granted_by')
        self.assertEqual(response.status_code, 200, response.content)
        user_item = _share_for_username(response.json()['results'], 'target')
        self.assertIn('email', user_item['user'])
        self.assertIn('email', user_item['granted_by'])

    def test_unknown_query_param_returns_422(self):
        self.assertEqual(self._get(f'{_list_url(self.secret)}?bogus=1').status_code, 422)

    def test_unknown_sort_returns_422(self):
        self.assertEqual(self._get(f'{_list_url(self.secret)}?sort=bogus').status_code, 422)

    def test_unknown_expand_returns_422(self):
        self.assertEqual(self._get(f'{_list_url(self.secret)}?expand=bogus').status_code, 422)

    def test_list_requires_read_scope(self):
        _, token = ApiToken.issue(user=self.owner, name='wronly', scopes=['shares:write'])
        self.assertEqual(self._get(_list_url(self.secret), token=token).status_code, 403)

    def test_list_without_token_returns_401(self):
        self.assertEqual(self.client.get(_list_url(self.secret)).status_code, 401)

    def test_list_invisible_secret_returns_404(self):
        other = make_user('other')
        hidden = new_secret(other, access_policy=AccessPolicy.HIDDEN, name='Hidden')
        self.assertEqual(self._get(_list_url(hidden)).status_code, 404)

    def test_list_no_n_plus_one(self):
        from django.contrib.auth.models import Group

        for i in range(5):
            user = make_user(f'u{i}')
            SharedSecretData.objects.create(secret=self.secret, user=user, granted_by=self.owner)
            group = Group.objects.create(name=f'g{i}')
            SharedSecretData.objects.create(secret=self.secret, group=group, granted_by=self.owner)

        url = f'{_list_url(self.secret)}?expand=user,group,granted_by&page_size=200'
        with CaptureQueriesContext(connection) as few:
            self.assertEqual(self._get(url).status_code, 200)

        for i in range(5, 15):
            user = make_user(f'u{i}')
            SharedSecretData.objects.create(secret=self.secret, user=user, granted_by=self.owner)
        with CaptureQueriesContext(connection) as many:
            self.assertEqual(self._get(url).status_code, 200)

        self.assertEqual(len(few.captured_queries), len(many.captured_queries))


@override_settings(**COMMON_OVERRIDES)
class ShareCreateTest(TestCase):
    def setUp(self):
        from django.contrib.auth.models import Group

        self.owner = make_user('owner')
        self.target = make_user('target')
        self.group = Group.objects.create(name='ops')
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN, name='shared-secret')
        _, self.token = ApiToken.issue(user=self.owner, name='sharer', scopes=['shares:write'])

    def _post(self, body, token=None):
        import json

        return self.client.post(
            _list_url(self.secret),
            data=json.dumps(body),
            content_type='application/json',
            **auth_header(token or self.token),
        )

    def test_create_user_share(self):
        response = self._post({'user': self.target.pk, 'grant_description': 'access'})
        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertEqual(body['user']['id'], self.target.pk)
        self.assertIsNone(body['group'])
        self.assertTrue(SharedSecretData.objects.filter(secret=self.secret, user=self.target).exists())

    def test_create_group_share(self):
        response = self._post({'group': self.group.pk, 'grant_description': 'team access'})
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()['group']['id'], self.group.pk)

    def test_create_with_expires_at(self):
        until = now() + timedelta(days=7)
        response = self._post({'user': self.target.pk, 'grant_description': 'temp', 'expires_at': until.isoformat()})
        self.assertEqual(response.status_code, 201, response.content)
        self.assertIsNotNone(response.json()['expires_at'])
        share = SharedSecretData.objects.get(secret=self.secret, user=self.target)
        self.assertIsNotNone(share.granted_until)

    def test_create_both_user_and_group_returns_422(self):
        response = self._post({'user': self.target.pk, 'group': self.group.pk, 'grant_description': 'x'})
        self.assertEqual(response.status_code, 422, response.content)

    def test_create_neither_user_nor_group_returns_422(self):
        response = self._post({'grant_description': 'x'})
        self.assertEqual(response.status_code, 422, response.content)

    def test_create_duplicate_active_share_returns_422(self):
        self._post({'user': self.target.pk, 'grant_description': 'first'})
        response = self._post({'user': self.target.pk, 'grant_description': 'second'})
        self.assertEqual(response.status_code, 422, response.content)
        self.assertEqual(SharedSecretData.objects.filter(secret=self.secret, user=self.target).count(), 1)

    def test_create_after_expiry_works(self):
        SharedSecretData.objects.create(
            secret=self.secret, user=self.target, granted_by=self.owner, granted_until=now() - timedelta(days=1)
        )
        response = self._post({
            'user': self.target.pk,
            'grant_description': 're-share',
            'expires_at': (now() + timedelta(days=7)).isoformat(),
        })
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(SharedSecretData.objects.filter(secret=self.secret, user=self.target).count(), 1)

    def test_create_writes_audit_log(self):
        self._post({'user': self.target.pk, 'grant_description': 'access'})
        self.assertEqual(
            LogEntry.objects.filter(secret=self.secret, category=AuditLogCategoryChoices.SECRET_SHARED).count(),
            1,
        )

    def test_superuser_share_audit_category(self):
        admin = make_user('admin', superuser=True)
        _, admin_token = ApiToken.issue(user=admin, name='su', scopes=['shares:write'])
        response = self._post({'user': self.target.pk, 'grant_description': 'su-share'}, token=admin_token)
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(
            LogEntry.objects.filter(
                secret=self.secret, category=AuditLogCategoryChoices.SECRET_SUPERUSER_SHARED
            ).count(),
            1,
        )

    def test_create_requires_shares_write_scope(self):
        _, token = ApiToken.issue(user=self.owner, name='writeonly', scopes=['secrets:write'])
        response = self._post({'user': self.target.pk, 'grant_description': 'x'}, token=token)
        self.assertEqual(response.status_code, 403)

    def test_create_without_share_access_returns_403(self):
        outsider = make_user('outsider')
        _, token = ApiToken.issue(user=outsider, name='out', scopes=['shares:write'])
        # outsider cannot even see the hidden secret
        response = self._post({'user': self.target.pk, 'grant_description': 'x'}, token=token)
        self.assertIn(response.status_code, (403, 404))

    def test_create_unknown_user_returns_422(self):
        response = self._post({'user': 999999, 'grant_description': 'x'})
        self.assertEqual(response.status_code, 422, response.content)


@override_settings(**COMMON_OVERRIDES)
class ShareDeleteTest(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.target = make_user('target')
        self.admin = make_user('admin', superuser=True)
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN, name='shared-secret')
        _, self.token = ApiToken.issue(user=self.owner, name='sharer', scopes=['shares:write'])

    def _delete(self, share_id, token=None):
        return self.client.delete(_detail_url(self.secret, share_id), **auth_header(token or self.token))

    def test_delete_removes_share(self):
        share = SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        response = self._delete(share.pk)
        self.assertEqual(response.status_code, 204, getattr(response, 'content', b''))
        self.assertFalse(SharedSecretData.objects.filter(pk=share.pk).exists())

    def test_delete_writes_audit_log(self):
        share = SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        self._delete(share.pk)
        self.assertEqual(
            LogEntry.objects.filter(secret=self.secret, category=AuditLogCategoryChoices.SECRET_SHARE_REMOVED).count(),
            1,
        )

    def test_delete_superuser_audit_category(self):
        share = SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        _, admin_token = ApiToken.issue(user=self.admin, name='su', scopes=['shares:write'])
        response = self._delete(share.pk, token=admin_token)
        self.assertEqual(response.status_code, 204)
        self.assertEqual(
            LogEntry.objects.filter(
                secret=self.secret, category=AuditLogCategoryChoices.SECRET_SUPERUSER_SHARE_REMOVED
            ).count(),
            1,
        )

    def test_delete_unknown_share_returns_404(self):
        self.assertEqual(self._delete(999999).status_code, 404)

    def test_delete_share_of_other_secret_returns_404(self):
        other = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN, name='other')
        share = SharedSecretData.objects.create(secret=other, user=self.target, granted_by=self.owner)
        self.assertEqual(self._delete(share.pk).status_code, 404)

    def test_delete_requires_shares_write_scope(self):
        share = SharedSecretData.objects.create(secret=self.secret, user=self.target, granted_by=self.owner)
        _, token = ApiToken.issue(user=self.owner, name='writeonly', scopes=['secrets:write'])
        self.assertEqual(self._delete(share.pk, token=token).status_code, 403)
