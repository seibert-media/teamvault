import uuid

from django.test import SimpleTestCase

from teamvault.apps.accounts.ldap_uuid import canonicalize_entry_uuid, entry_uuid_filter_term

GUID = uuid.UUID('12345678-1234-5678-9abc-123456789abc')


class CanonicalizeEntryUUIDTests(SimpleTestCase):
    def test_passes_through_string_uuid(self):
        self.assertEqual(
            canonicalize_entry_uuid('5a02e51c-8d9e-4f5a-b8e1-2f3a4b5c6d7e'),
            '5a02e51c-8d9e-4f5a-b8e1-2f3a4b5c6d7e',
        )

    def test_decodes_utf8_bytes(self):
        self.assertEqual(
            canonicalize_entry_uuid(b'5a02e51c-8d9e-4f5a-b8e1-2f3a4b5c6d7e'),
            '5a02e51c-8d9e-4f5a-b8e1-2f3a4b5c6d7e',
        )

    def test_canonicalizes_binary_guid_as_little_endian(self):
        self.assertEqual(canonicalize_entry_uuid(GUID.bytes_le), str(GUID))

    def test_rejects_undecodable_bytes(self):
        self.assertIsNone(canonicalize_entry_uuid(b'\xff\xfe\xfd'))

    def test_rejects_overlong_value(self):
        self.assertIsNone(canonicalize_entry_uuid('x' * 37))

    def test_rejects_empty_value(self):
        self.assertIsNone(canonicalize_entry_uuid(''))
        self.assertIsNone(canonicalize_entry_uuid(b''))
        self.assertIsNone(canonicalize_entry_uuid(None))

    def test_passes_through_non_uuid_string_id(self):
        self.assertEqual(canonicalize_entry_uuid('some-opaque-id'), 'some-opaque-id')


class EntryUUIDFilterTermTests(SimpleTestCase):
    def test_uuid_value_matches_string_and_binary_forms(self):
        term = entry_uuid_filter_term('objectGUID', str(GUID))

        escaped_binary = ''.join(f'\\{byte:02x}' for byte in GUID.bytes_le)
        self.assertEqual(term, f'(|(objectGUID={GUID})(objectGUID={escaped_binary}))')

    def test_non_uuid_value_gets_single_escaped_term(self):
        self.assertEqual(entry_uuid_filter_term('entryUUID', 'a(b)c'), r'(entryUUID=a\28b\29c)')
