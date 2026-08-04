from datetime import timedelta
from urllib.parse import quote

from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now

from teamvault.apps.accounts.models import ApiToken
from teamvault.apps.secrets.enums import AccessPolicy
from teamvault.apps.secrets.models import SecretChange, SharedSecretData
from teamvault.apps.secrets.services.revision import RevisionService
from teamvault.apps.secrets.tests.utils import COMMON_OVERRIDES, make_user, new_secret


def auth_header(token_string):
    return {'HTTP_AUTHORIZATION': f'Bearer {token_string}'}


def _list_url(secret) -> str:
    return f'/api/v2/secrets/{secret.hashid}/revisions'


def _detail_url(secret, revision_hashid) -> str:
    return f'/api/v2/secrets/{secret.hashid}/revisions/{revision_hashid}'


def _changes(secret):
    return list(SecretChange.objects.filter(secret=secret).order_by('created'))


@override_settings(**COMMON_OVERRIDES)
class RevisionListTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.owner = make_user('owner')
        cls.secret = new_secret(cls.owner, access_policy=AccessPolicy.HIDDEN, name='secret-1')
        # second edit (metadata change) -> a second SecretChange in the chain
        cls.secret.name = 'secret-1-renamed'
        cls.secret.save(update_fields=['name'])
        RevisionService.save_payload(
            secret=cls.secret, actor=cls.owner, payload={'password': 'second-pw'}, skip_acl=True
        )
        _, cls.token = ApiToken.issue(user=cls.owner, name='reader', scopes=['secrets:read'])

    def _get(self, path, token=None):
        return self.client.get(path, **auth_header(token or self.token))

    def test_list_returns_full_chain_newest_first(self):
        response = self._get(_list_url(self.secret))
        self.assertEqual(response.status_code, 200, response.content)
        results = response.json()['results']
        self.assertEqual(len(results), 2)
        created = [item['created_at'] for item in results]
        self.assertEqual(created, sorted(created, reverse=True))
        # newest first; oldest has no parent, newest links to oldest
        newest, oldest = results
        self.assertIsNone(oldest['parent_hashid'])
        self.assertEqual(newest['parent_hashid'], oldest['hashid'])

    def test_snapshot_fields_present(self):
        results = self._get(_list_url(self.secret)).json()['results']
        newest = results[0]
        self.assertEqual(newest['name'], 'secret-1-renamed')
        self.assertEqual(newest['access_policy'], 'hidden')
        self.assertEqual(newest['status'], 'ok')
        self.assertIn('description', newest)
        self.assertIn('username', newest)
        self.assertIn('url', newest)
        self.assertIn('filename', newest)
        self.assertIn('needs_changing_on_leave', newest)
        self.assertEqual(newest['actor']['username'], 'owner')
        self.assertIsNone(newest['scrubbed_at'])
        self.assertIsNone(newest['scrubbed_by'])

    def test_payload_ref_exposed(self):
        newest = self._get(_list_url(self.secret)).json()['results'][0]
        self.assertIn('hashid', newest['payload'])
        self.assertIn('set_by', newest['payload'])

    def test_dedup_payload_shared_hashid(self):
        # save identical plaintext again as a metadata-only change so a new SecretChange row
        # references the same (deduplicated) payload revision
        self.secret.refresh_from_db()
        self.secret.url = 'https://example.test'
        self.secret.save(update_fields=['url'])
        RevisionService.save_payload(
            secret=self.secret, actor=self.owner, payload={'password': 'second-pw'}, skip_acl=True
        )
        results = self._get(_list_url(self.secret)).json()['results']
        payload_hashids = [item['payload']['hashid'] for item in results]
        # newest two share the same payload hashid (identical plaintext, deduplicated)
        self.assertEqual(payload_hashids[0], payload_hashids[1])

    def test_restore_sets_restored_from_hashid(self):
        self.secret.refresh_from_db()
        target = _changes(self.secret)[0]
        RevisionService.restore_to_change(secret=self.secret, actor=self.owner, change=target)
        results = self._get(_list_url(self.secret)).json()['results']
        restore_change = results[0]
        self.assertEqual(restore_change['restored_from_hashid'], target.hashid)

    def test_filter_by_actor(self):
        other = make_user('other')
        SharedSecretData.objects.create(secret=self.secret, user=other)
        RevisionService.save_payload(secret=self.secret, actor=other, payload={'password': 'third-pw'}, skip_acl=True)
        response = self._get(f'{_list_url(self.secret)}?actor={other.pk}')
        self.assertEqual(response.status_code, 200, response.content)
        results = response.json()['results']
        self.assertTrue(all(item['actor']['id'] == other.pk for item in results))
        self.assertEqual(len(results), 1)

    def test_filter_created_after_before(self):
        future = quote((now() + timedelta(days=1)).isoformat())
        results = self._get(f'{_list_url(self.secret)}?created_after={future}')
        self.assertEqual(results.json()['count'], 0)
        results = self._get(f'{_list_url(self.secret)}?created_before={future}')
        self.assertEqual(results.json()['count'], 2)

    def test_date_filter_bounds_are_inclusive(self):
        # Both filters document "at or after"/"at or before": a revision's exact timestamp matches.
        newest = _changes(self.secret)[-1]
        exact = quote(newest.created.isoformat())
        after = self._get(f'{_list_url(self.secret)}?created_after={exact}').json()
        self.assertIn(newest.hashid, [item['hashid'] for item in after['results']])
        before = self._get(f'{_list_url(self.secret)}?created_before={exact}').json()
        self.assertIn(newest.hashid, [item['hashid'] for item in before['results']])

    def test_sort_asc(self):
        results = self._get(f'{_list_url(self.secret)}?sort=created_at').json()['results']
        created = [item['created_at'] for item in results]
        self.assertEqual(created, sorted(created))

    def test_expand_actor(self):
        newest = self._get(f'{_list_url(self.secret)}?expand=actor').json()['results'][0]
        self.assertIn('email', newest['actor'])

    def test_unknown_query_param_returns_422(self):
        self.assertEqual(self._get(f'{_list_url(self.secret)}?bogus=1').status_code, 422)

    def test_unknown_sort_returns_422(self):
        self.assertEqual(self._get(f'{_list_url(self.secret)}?sort=name').status_code, 422)

    def test_unknown_expand_returns_422(self):
        self.assertEqual(self._get(f'{_list_url(self.secret)}?expand=parent').status_code, 422)

    def test_list_requires_read_scope(self):
        _, token = ApiToken.issue(user=self.owner, name='dataonly', scopes=['secrets:data:read'])
        self.assertEqual(self._get(_list_url(self.secret), token=token).status_code, 403)

    def test_list_without_token_returns_401(self):
        self.assertEqual(self.client.get(_list_url(self.secret)).status_code, 401)

    def test_list_invisible_secret_returns_404(self):
        other = make_user('stranger')
        hidden = new_secret(other, access_policy=AccessPolicy.HIDDEN, name='Hidden')
        self.assertEqual(self._get(_list_url(hidden)).status_code, 404)

    def test_list_no_n_plus_one(self):
        actors = [make_user(f'a{i}') for i in range(3)]
        for actor in actors:
            SharedSecretData.objects.create(secret=self.secret, user=actor)
            RevisionService.save_payload(
                secret=self.secret, actor=actor, payload={'password': f'pw-{actor.pk}'}, skip_acl=True
            )

        url = f'{_list_url(self.secret)}?expand=actor&page_size=200'
        with CaptureQueriesContext(connection) as few:
            self.assertEqual(self._get(url).status_code, 200)

        more_actors = [make_user(f'b{i}') for i in range(5)]
        for actor in more_actors:
            SharedSecretData.objects.create(secret=self.secret, user=actor)
            RevisionService.save_payload(
                secret=self.secret, actor=actor, payload={'password': f'pw2-{actor.pk}'}, skip_acl=True
            )
        with CaptureQueriesContext(connection) as many:
            self.assertEqual(self._get(url).status_code, 200)

        self.assertEqual(len(few.captured_queries), len(many.captured_queries))

    def test_revision_hashid_resolves_at_data_endpoint(self):
        _, data_token = ApiToken.issue(user=self.owner, name='data', scopes=['secrets:read', 'secrets:data:read'])
        revision_hashid = self._get(_list_url(self.secret), token=data_token).json()['results'][0]['hashid']
        response = self._get(f'{_detail_url(self.secret, revision_hashid)}/data', token=data_token)
        self.assertEqual(response.status_code, 200, response.content)


@override_settings(**COMMON_OVERRIDES)
class RevisionDetailTest(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.secret = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN, name='secret-1')
        _, self.token = ApiToken.issue(user=self.owner, name='reader', scopes=['secrets:read'])

    def _get(self, path, token=None):
        return self.client.get(path, **auth_header(token or self.token))

    def test_detail_returns_revision(self):
        change = _changes(self.secret)[0]
        response = self._get(_detail_url(self.secret, change.hashid))
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['hashid'], change.hashid)

    def test_detail_unknown_revision_returns_404(self):
        self.assertEqual(self._get(_detail_url(self.secret, 'doesnotexist')).status_code, 404)

    def test_detail_revision_of_other_secret_returns_404(self):
        other = new_secret(self.owner, access_policy=AccessPolicy.HIDDEN, name='other')
        other_change = _changes(other)[0]
        self.assertEqual(self._get(_detail_url(self.secret, other_change.hashid)).status_code, 404)

    def test_detail_invisible_secret_returns_404(self):
        stranger = make_user('stranger')
        hidden = new_secret(stranger, access_policy=AccessPolicy.HIDDEN, name='Hidden')
        change = _changes(hidden)[0]
        self.assertEqual(self._get(_detail_url(hidden, change.hashid)).status_code, 404)

    def test_detail_requires_read_scope(self):
        change = _changes(self.secret)[0]
        _, token = ApiToken.issue(user=self.owner, name='dataonly', scopes=['secrets:data:read'])
        self.assertEqual(self._get(_detail_url(self.secret, change.hashid), token=token).status_code, 403)

    def test_detail_expand_actor(self):
        change = _changes(self.secret)[0]
        body = self._get(f'{_detail_url(self.secret, change.hashid)}?expand=actor').json()
        self.assertIn('email', body['actor'])

    def test_detail_unknown_query_param_returns_422(self):
        change = _changes(self.secret)[0]
        self.assertEqual(self._get(f'{_detail_url(self.secret, change.hashid)}?bogus=1').status_code, 422)

    def test_scrubbed_revision_exposes_scrub_state(self):
        admin = make_user('admin', superuser=True)
        # add a second change so the first has a child and can be scrubbed against a parent
        self.secret.name = 'renamed'
        self.secret.save(update_fields=['name'])
        RevisionService.save_payload(
            secret=self.secret, actor=self.owner, payload={'password': 'new-pw'}, skip_acl=True
        )
        target = _changes(self.secret)[-1]
        RevisionService.delete_change(change=target, actor=admin)
        body = self._get(_detail_url(self.secret, target.hashid)).json()
        self.assertIsNotNone(body['scrubbed_at'])
        self.assertEqual(body['scrubbed_by']['username'], 'admin')
