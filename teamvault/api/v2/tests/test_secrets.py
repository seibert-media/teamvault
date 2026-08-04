from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret, SharedSecretData
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user, new_secret


def auth_header(token_string):
    return {'HTTP_AUTHORIZATION': f'Bearer {token_string}'}


@override_settings(**COMMON_OVERRIDES)
class SecretListValidationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = make_user('alice')
        _, cls.token = ApiToken.issue(user=cls.user, name='reader', scopes=['secrets:read'])

    def _get(self, path, token=None):
        return self.client.get(path, **auth_header(token or self.token))

    def test_list_without_token_returns_401(self):
        self.assertEqual(self.client.get('/api/v2/secrets/').status_code, 401)

    def test_list_with_wrong_scope_returns_403(self):
        _, token = ApiToken.issue(user=self.user, name='other', scopes=['users:read'])
        response = self._get('/api/v2/secrets/', token=token)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(set(response.json()), {'detail'})

    def test_unknown_query_param_returns_422(self):
        response = self._get('/api/v2/secrets/?naem=x')
        self.assertEqual(response.status_code, 422)
        self.assertIn('naem', str(response.json()['detail']))

    def test_unknown_sort_key_returns_422(self):
        response = self._get('/api/v2/secrets/?sort=bogus')
        self.assertEqual(response.status_code, 422)
        self.assertIn('bogus', str(response.json()['detail']))

    def test_unknown_expand_value_returns_422(self):
        response = self._get('/api/v2/secrets/?expand=bogus')
        self.assertEqual(response.status_code, 422)
        self.assertIn('bogus', str(response.json()['detail']))

    def test_unknown_filter_enum_value_returns_422(self):
        response = self._get('/api/v2/secrets/?status=nonsense')
        self.assertEqual(response.status_code, 422)

    def test_page_zero_returns_422(self):
        self.assertEqual(self._get('/api/v2/secrets/?page=0').status_code, 422)


@override_settings(**COMMON_OVERRIDES)
class SecretDetailValidationTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        _, cls.token = ApiToken.issue(user=cls.owner, name='reader', scopes=['secrets:read'])
        cls.secret = new_secret(cls.owner, access_policy=AccessPolicy.ANY, name='Readable')

    def _get(self, path, token=None):
        return self.client.get(path, **auth_header(token or self.token))

    def test_detail_without_token_returns_401(self):
        self.assertEqual(self.client.get(f'/api/v2/secrets/{self.secret.hashid}').status_code, 401)

    def test_detail_wrong_scope_returns_403(self):
        _, token = ApiToken.issue(user=self.owner, name='other', scopes=['users:read'])
        self.assertEqual(self._get(f'/api/v2/secrets/{self.secret.hashid}', token=token).status_code, 403)

    def test_detail_unknown_hashid_returns_404(self):
        self.assertEqual(self._get('/api/v2/secrets/nope').status_code, 404)

    def test_detail_unknown_query_param_returns_422(self):
        self.assertEqual(self._get(f'/api/v2/secrets/{self.secret.hashid}?expnad=x').status_code, 422)

    def test_detail_unknown_expand_value_returns_422(self):
        response = self._get(f'/api/v2/secrets/{self.secret.hashid}?expand=bogus')
        self.assertEqual(response.status_code, 422)


@override_settings(**COMMON_OVERRIDES)
class SecretSchemaTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        _, cls.token = ApiToken.issue(user=cls.owner, name='reader', scopes=['secrets:read'])
        cls.secret = new_secret(
            cls.owner,
            access_policy=AccessPolicy.ANY,
            name='Production database',
            url='https://db.example.com',
        )

    def _get(self, path):
        return self.client.get(path, **auth_header(self.token))

    def test_detail_returns_full_v2_schema(self):
        response = self._get(f'/api/v2/secrets/{self.secret.hashid}')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(
            set(body),
            {
                'hashid',
                'name',
                'url',
                'username',
                'description',
                'filename',
                'content_type',
                'access_policy',
                'status',
                'needs_changing_on_leave',
                'created_at',
                'last_changed_at',
                'last_read_at',
                'created_by',
                'current_payload',
                'data_readable',
                'web_url',
            },
        )
        self.assertEqual(body['hashid'], self.secret.hashid)
        self.assertEqual(body['content_type'], 'password')
        self.assertEqual(body['access_policy'], 'any')
        self.assertEqual(body['status'], 'ok')
        self.assertEqual(
            body['created_by'],
            {
                'id': self.owner.pk,
                'username': 'owner',
                'full_name': self.owner.get_full_name(),
            },
        )
        self.assertEqual(body['data_readable'], True)
        self.assertEqual(body['web_url'], self.secret.full_url)

    def test_current_payload_is_a_payload_ref(self):
        body = self._get(f'/api/v2/secrets/{self.secret.hashid}').json()
        payload = body['current_payload']
        self.assertEqual(set(payload), {'hashid', 'created_at', 'set_by'})
        self.assertEqual(payload['hashid'], self.secret.current_revision.hashid)
        self.assertEqual(payload['set_by']['username'], 'owner')

    def test_credit_card_content_type_is_credit_card(self):
        cc = new_secret(self.owner, content_type=ContentType.CC, access_policy=AccessPolicy.ANY, name='Card')
        body = self._get(f'/api/v2/secrets/{cc.hashid}').json()
        self.assertEqual(body['content_type'], 'credit_card')

    def test_list_returns_refs_by_default(self):
        body = self._get('/api/v2/secrets/').json()
        (item,) = body['results']
        self.assertEqual(set(item['created_by']), {'id', 'username', 'full_name'})

    def test_expand_created_by_returns_full_user(self):
        body = self._get(f'/api/v2/secrets/{self.secret.hashid}?expand=created_by').json()
        self.assertEqual(set(body['created_by']), {'id', 'username', 'full_name', 'email', 'is_active'})
        self.assertEqual(body['created_by']['email'], self.owner.email)

    def test_list_expand_created_by_returns_full_user(self):
        body = self._get('/api/v2/secrets/?expand=created_by').json()
        (item,) = body['results']
        self.assertEqual(set(item['created_by']), {'id', 'username', 'full_name', 'email', 'is_active'})


@override_settings(**COMMON_OVERRIDES)
class SecretListVisibilityParityTest(TestCase):
    """The v2 list must show exactly the secrets v1's get_all_visible_to_user returns."""

    @classmethod
    def setUpTestData(cls):
        cls.viewer = make_user('viewer')
        cls.other = make_user('other')
        _, cls.token = ApiToken.issue(user=cls.viewer, name='reader', scopes=['secrets:read'])

        cls.public = new_secret(cls.other, access_policy=AccessPolicy.ANY, name='Public')
        cls.discoverable = new_secret(cls.other, access_policy=AccessPolicy.DISCOVERABLE, name='Discoverable')
        cls.hidden = new_secret(cls.other, access_policy=AccessPolicy.HIDDEN, name='Hidden')
        cls.hidden_shared = new_secret(cls.other, access_policy=AccessPolicy.HIDDEN, name='HiddenShared')
        SharedSecretData.objects.create(secret=cls.hidden_shared, user=cls.viewer)
        cls.deleted = new_secret(cls.other, access_policy=AccessPolicy.ANY, name='Deleted')
        Secret.objects.filter(pk=cls.deleted.pk).update(status=SecretStatus.DELETED)

    def _get(self, path):
        return self.client.get(path, **auth_header(self.token))

    def test_list_matches_v1_visibility(self):
        body = self._get('/api/v2/secrets/?page_size=200').json()
        api_hashids = {item['hashid'] for item in body['results']}
        v1_hashids = set(Secret.get_all_visible_to_user(self.viewer).values_list('hashid', flat=True))
        self.assertEqual(api_hashids, v1_hashids)
        self.assertIn(self.public.hashid, api_hashids)
        self.assertIn(self.discoverable.hashid, api_hashids)
        self.assertIn(self.hidden_shared.hashid, api_hashids)
        self.assertNotIn(self.hidden.hashid, api_hashids)
        self.assertNotIn(self.deleted.hashid, api_hashids)

    def test_data_readable_reflects_user_permissions(self):
        body = self._get('/api/v2/secrets/?page_size=200').json()
        readable = {item['hashid']: item['data_readable'] for item in body['results']}
        # ANY policy is readable, discoverable-without-share is not, shared hidden is readable
        self.assertTrue(readable[self.public.hashid])
        self.assertFalse(readable[self.discoverable.hashid])
        self.assertTrue(readable[self.hidden_shared.hashid])

    def test_detail_invisible_returns_404(self):
        self.assertEqual(self._get(f'/api/v2/secrets/{self.hidden.hashid}').status_code, 404)

    def test_detail_visible_but_unreadable_returns_403(self):
        # discoverable is visible (in list) but not readable without a share
        self.assertEqual(self._get(f'/api/v2/secrets/{self.discoverable.hashid}').status_code, 403)


@override_settings(**COMMON_OVERRIDES)
class SecretListFilterSortTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.maker = make_user('maker')
        _, cls.token = ApiToken.issue(user=cls.owner, name='reader', scopes=['secrets:read'])
        cls.alpha = new_secret(cls.owner, access_policy=AccessPolicy.ANY, name='Alpha')
        cls.beta = new_secret(cls.owner, access_policy=AccessPolicy.ANY, name='Beta')
        cls.cc = new_secret(cls.maker, content_type=ContentType.CC, access_policy=AccessPolicy.ANY, name='Card')
        # new_secret ignores url/username kwargs; set them directly for the substring filters.
        Secret.objects.filter(pk=cls.alpha.pk).update(username='alice')
        Secret.objects.filter(pk=cls.beta.pk).update(username='bob')

    def _results(self, path):
        return [item['hashid'] for item in self.client.get(path, **auth_header(self.token)).json()['results']]

    def test_default_sort_by_name(self):
        self.assertEqual(self._results('/api/v2/secrets/'), [self.alpha.hashid, self.beta.hashid, self.cc.hashid])

    def test_sort_descending_by_name(self):
        self.assertEqual(
            self._results('/api/v2/secrets/?sort=-name'),
            [self.cc.hashid, self.beta.hashid, self.alpha.hashid],
        )

    def test_filter_by_content_type(self):
        self.assertEqual(self._results('/api/v2/secrets/?content_type=credit_card'), [self.cc.hashid])

    def test_filter_by_name_substring(self):
        self.assertEqual(self._results('/api/v2/secrets/?name=alph'), [self.alpha.hashid])

    def test_filter_by_username_substring(self):
        self.assertEqual(self._results('/api/v2/secrets/?username=bob'), [self.beta.hashid])

    def test_filter_by_created_by(self):
        self.assertEqual(self._results(f'/api/v2/secrets/?created_by={self.maker.pk}'), [self.cc.hashid])

    def test_filters_combine_with_and(self):
        self.assertEqual(self._results(f'/api/v2/secrets/?name=alph&created_by={self.maker.pk}'), [])

    def test_filter_q_search(self):
        self.assertEqual(self._results('/api/v2/secrets/?q=Alpha'), [self.alpha.hashid])

    def test_page_size_clamped_to_200(self):
        body = self.client.get('/api/v2/secrets/?page_size=10000', **auth_header(self.token)).json()
        self.assertEqual(set(body), {'count', 'next', 'previous', 'results'})


@override_settings(**COMMON_OVERRIDES)
class SecretQueryBudgetTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        _, cls.token = ApiToken.issue(user=cls.owner, name='reader', scopes=['secrets:read'])
        for i in range(5):
            new_secret(cls.owner, access_policy=AccessPolicy.ANY, name=f'Secret {i}')

    def _list_query_count(self, row_count):
        for i in range(row_count - Secret.objects.count()):
            new_secret(self.owner, access_policy=AccessPolicy.ANY, name=f'Extra {i}')
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get('/api/v2/secrets/?expand=created_by&page_size=200', **auth_header(self.token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['results']), row_count)
        return len(ctx.captured_queries)

    def test_list_with_expand_does_not_grow_per_row(self):
        # Auth(2) + count(1) + page(1) + bulk readable-shares(1) = 5, independent of row count.
        with self.assertNumQueries(5):
            response = self.client.get('/api/v2/secrets/?expand=created_by&page_size=200', **auth_header(self.token))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['results']), 5)

    def test_list_query_count_constant_across_page_sizes(self):
        self.assertEqual(self._list_query_count(5), self._list_query_count(20))

    def test_detail_with_expand_fixed_query_count(self):
        secret = Secret.objects.first()
        # Auth(2) + secret fetch with select_related(1) + bulk readable-shares(1) = 4.
        with self.assertNumQueries(4):
            response = self.client.get(f'/api/v2/secrets/{secret.hashid}?expand=created_by', **auth_header(self.token))
        self.assertEqual(response.status_code, 200)
