import uuid

from ldap.filter import escape_filter_chars

# matches GroupUUIDMapping.ldap_uuid / User.ldap_uuid
LDAP_UUID_MAX_LENGTH = 36
BINARY_GUID_LENGTH = 16


def canonicalize_ldap_uuid(value):
    """
    Normalize a raw LDAP unique-id attribute value to its canonical string form,
    or None if the value is unusable.

    Active Directory's objectGUID is 16 raw bytes in little-endian mixed layout;
    any 16-byte value is treated as such, matching how AD tooling renders GUIDs.
    """
    if isinstance(value, bytes):
        if len(value) == BINARY_GUID_LENGTH:
            return str(uuid.UUID(bytes_le=value))
        try:
            value = value.decode()
        except UnicodeDecodeError:
            return None
    if not value or len(value) > LDAP_UUID_MAX_LENGTH:
        return None
    return value


def ldap_uuid_filter_term(attr, canonical):
    """
    LDAP filter term matching the attribute against a canonical entry-uuid string.

    If the value parses as a UUID, the term also matches the binary little-endian
    form. The stored canonical string never matches a binary attribute like
    objectGUID directly, which would make liveness checks read every group as gone.
    """
    string_term = f'({attr}={escape_filter_chars(canonical)})'
    try:
        binary = uuid.UUID(canonical).bytes_le
    except ValueError:
        return string_term
    escaped_binary = ''.join(f'\\{byte:02x}' for byte in binary)
    return f'(|{string_term}({attr}={escaped_binary}))'
