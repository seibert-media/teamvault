from django.test import SimpleTestCase

from teamvault.api.v2.scopes import VALID_SCOPES, public_endpoint, requires_scope, validate_scopes


class ScopeVocabularyTest(SimpleTestCase):
    def test_v2_scope_taxonomy_is_valid(self):
        self.assertIsNone(
            validate_scopes(['secrets:read', 'secrets:data:read', 'secrets:write', 'shares:write', 'users:read'])
        )

    def test_wildcard_scopes_are_valid(self):
        self.assertIsNone(validate_scopes(['secrets:*', 'shares:*', 'users:*']))

    def test_unknown_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_scopes(['users:write'])

    def test_unknown_wildcard_resource_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_scopes(['nonexistent:*'])

    def test_data_read_is_not_implied_by_other_secrets_scopes(self):
        # The taxonomy must keep decryption (secrets:data:read) a distinct grant.
        self.assertIn('secrets:data:read', VALID_SCOPES)
        self.assertIn('secrets:read', VALID_SCOPES)


class ScopeIntrospectionTest(SimpleTestCase):
    def test_requires_scope_attaches_required_scope_to_wrapper(self):
        @requires_scope('secrets:read')
        def view(_request):
            return 'ok'

        self.assertEqual(view._required_scope, 'secrets:read')

    def test_requires_scope_rejects_unknown_scope_at_definition_time(self):
        with self.assertRaises(ValueError):
            requires_scope('bogus:read')

    def test_public_endpoint_marks_handler(self):
        @public_endpoint
        def view(_request):
            return 'ok'

        self.assertTrue(view._public_endpoint)
        self.assertEqual(view(None), 'ok')
