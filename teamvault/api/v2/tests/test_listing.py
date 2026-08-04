from collections import UserList

from django.test import RequestFactory, SimpleTestCase
from ninja.errors import HttpError
from pydantic import ValidationError

from teamvault.api.v2.listing import (
    MAX_PAGE_SIZE,
    PageNumberEnvelopePagination,
    parse_expand,
    parse_sort,
    reject_unknown_query_params,
)

SORT_FIELDS = {'name': 'name', 'created_at': 'created'}


class ParseSortTest(SimpleTestCase):
    def test_no_sort_returns_default(self):
        self.assertEqual(parse_sort(None, SORT_FIELDS, default=['name']), ['name'])
        self.assertEqual(parse_sort('', SORT_FIELDS, default=['name']), ['name'])

    def test_single_key_maps_to_model_field(self):
        self.assertEqual(parse_sort('created_at', SORT_FIELDS, default=['name']), ['created'])

    def test_descending_prefix_and_multiple_keys(self):
        self.assertEqual(parse_sort('-created_at,name', SORT_FIELDS, default=['name']), ['-created', 'name'])

    def test_unknown_key_raises_422(self):
        with self.assertRaises(HttpError) as ctx:
            parse_sort('bogus', SORT_FIELDS, default=['name'])
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn('bogus', str(ctx.exception))


class ParseExpandTest(SimpleTestCase):
    def test_no_expand_returns_empty_set(self):
        self.assertEqual(parse_expand(None, {'created_by'}), set())
        self.assertEqual(parse_expand('', {'created_by'}), set())

    def test_known_values_returned(self):
        self.assertEqual(parse_expand('created_by', {'created_by'}), {'created_by'})

    def test_unknown_value_raises_422_naming_the_offender(self):
        with self.assertRaises(HttpError) as ctx:
            parse_expand('bogus', {'created_by'})
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn('bogus', str(ctx.exception))


class RejectUnknownQueryParamsTest(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_allowed_params_pass(self):
        request = self.factory.get('/', {'name': 'x', 'page': '2'})
        reject_unknown_query_params(request, {'name', 'page'})

    def test_unknown_param_raises_422_naming_the_offender(self):
        request = self.factory.get('/', {'name': 'x', 'naem': 'y'})
        with self.assertRaises(HttpError) as ctx:
            reject_unknown_query_params(request, {'name'})
        self.assertEqual(ctx.exception.status_code, 422)
        self.assertIn('naem', str(ctx.exception))


class FakeQuerySet(UserList):
    def count(self):
        return len(self)


class PageNumberEnvelopePaginationTest(SimpleTestCase):
    def setUp(self):
        self.paginator = PageNumberEnvelopePagination()
        self.factory = RequestFactory()

    def _paginate(self, items, page, page_size, query=None):
        request = self.factory.get('/api/v2/secrets/', query or {})
        pagination = PageNumberEnvelopePagination.Input(page=page, page_size=page_size)
        return self.paginator.paginate_queryset(FakeQuerySet(items), pagination, request=request)

    def test_envelope_with_middle_page(self):
        result = self._paginate(range(120), page=2, page_size=50, query={'page': '2'})
        self.assertEqual(result['count'], 120)
        self.assertEqual(list(result['results']), list(range(50, 100)))
        self.assertIn('page=3', result['next'])
        self.assertIn('page=1', result['previous'])

    def test_first_page_has_no_previous(self):
        result = self._paginate(range(10), page=1, page_size=50)
        self.assertIsNone(result['previous'])
        self.assertIsNone(result['next'])

    def test_next_preserves_other_query_params(self):
        result = self._paginate(range(120), page=1, page_size=50, query={'name': 'dev'})
        self.assertIn('name=dev', result['next'])
        self.assertIn('page=2', result['next'])

    def test_page_size_is_clamped_silently(self):
        result = self._paginate(range(500), page=1, page_size=10_000, query={'page_size': '10000'})
        self.assertEqual(len(result['results']), MAX_PAGE_SIZE)
        self.assertIn('page_size=10000', result['next'])

    def test_page_zero_is_rejected_by_schema(self):
        with self.assertRaises(ValidationError):
            PageNumberEnvelopePagination.Input(page=0, page_size=50)
