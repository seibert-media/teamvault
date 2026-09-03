from datetime import timedelta

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now
from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret

from ..utils import COMMON_OVERRIDES, make_user, new_secret


def _names(response):
    return [row['name'] for row in response.json()['results']]


@override_settings(**COMMON_OVERRIDES)
class SecretListFilterTests(TestCase):
    def setUp(self):
        self.owner = make_user('owner')
        self.client.force_login(self.owner)
        self.url = reverse('api.secret_list')

    def _secret(self, name, *, status=SecretStatus.OK, last_read=None, **kwargs):
        secret = new_secret(self.owner, name=name, **kwargs)
        updates = {'status': status}
        if last_read is not None:
            updates['last_read'] = last_read
        Secret.objects.filter(pk=secret.pk).update(**updates)
        secret.refresh_from_db()
        return secret

    def test_filter_status_needs_changing(self):
        self._secret('ok-one', status=SecretStatus.OK)
        self._secret('stale-one', status=SecretStatus.NEEDS_CHANGING)
        self._secret('stale-two', status=SecretStatus.NEEDS_CHANGING)

        response = self.client.get(self.url, {'status': 'needs_changing'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(sorted(_names(response)), ['stale-one', 'stale-two'])

    def test_pagination_stable_on_tied_sort_key(self):
        base = now()
        for i in range(30):
            self._secret(f'tie-{i:02d}', last_read=base)  # all identical last_read
        page1 = self.client.get(self.url, {'ordering': 'last_read', 'page': 1})
        page2 = self.client.get(self.url, {'ordering': 'last_read', 'page': 2})
        names = _names(page1) + _names(page2)
        self.assertEqual(len(names), len(set(names)))  # no row on two pages / skipped

    def test_order_by_last_read_ascending(self):
        base = now()
        self._secret('newest', last_read=base)
        self._secret('oldest', last_read=base - timedelta(days=2))
        self._secret('middle', last_read=base - timedelta(days=1))

        response = self.client.get(self.url, {'ordering': 'last_read'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(_names(response), ['oldest', 'middle', 'newest'])

    def test_needs_changing_ordered_by_last_read(self):
        base = now()
        self._secret('ok', status=SecretStatus.OK, last_read=base)
        self._secret('stale-late', status=SecretStatus.NEEDS_CHANGING, last_read=base)
        self._secret(
            'stale-early',
            status=SecretStatus.NEEDS_CHANGING,
            last_read=base - timedelta(days=1),
        )

        response = self.client.get(self.url, {'status': 'needs_changing', 'ordering': 'last_read'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(_names(response), ['stale-early', 'stale-late'])

    def test_filter_content_type_string_value(self):
        self._secret('a-password', content_type=ContentType.PASSWORD)
        self._secret('a-file', content_type=ContentType.FILE)

        response = self.client.get(self.url, {'content_type': 'file'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(_names(response), ['a-file'])

    def test_filter_access_policy_string_value(self):
        self._secret('discoverable-one', access_policy=AccessPolicy.DISCOVERABLE)
        self._secret('hidden-one', access_policy=AccessPolicy.HIDDEN)

        response = self.client.get(self.url, {'access_policy': 'hidden'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(_names(response), ['hidden-one'])

    def test_filter_name_icontains(self):
        self._secret('production-db')
        self._secret('staging-db')
        self._secret('unrelated')

        response = self.client.get(self.url, {'name': 'db'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(sorted(_names(response)), ['production-db', 'staging-db'])

    def test_invalid_status_value_returns_400(self):
        response = self.client.get(self.url, {'status': 'bogus'})
        self.assertEqual(response.status_code, 400)

    def test_deleted_status_is_not_an_allowed_choice(self):
        response = self.client.get(self.url, {'status': 'deleted'})
        self.assertEqual(response.status_code, 400)
