from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from django_auth_ldap.config import LDAPSearch
from social_core.exceptions import AuthForbidden

User = get_user_model()


def _get_ldap_connection():
    return _LDAPUser(LDAPBackend(), username='').connection


def _get_attr(attrs, key):
    if key in attrs:
        values = attrs[key]
    elif isinstance(key, str) and key.encode() in attrs:
        values = attrs[key.encode()]
    else:
        return None
    if not values:
        return None
    value = values[0]
    return value.decode() if isinstance(value, bytes) else value


class UUIDLinkingLDAPBackend(LDAPBackend):
    """
    Link existing users by LDAP entryUUID to keep identity stable across username changes.
    Requires AUTH_LDAP_USER_ATTR_MAP['entry_uuid'] and AUTH_LDAP_USER_SEARCH to request entryUUID.
    """

    def get_or_build_user(self, username, ldap_user) -> tuple[User, bool]:
        entry_uuid_attr = settings.AUTH_LDAP_USER_ATTR_MAP.get('entry_uuid', 'entryUUID')
        entry_uuid = _get_attr(ldap_user.attrs, entry_uuid_attr)
        if entry_uuid:
            try:
                user = User.objects.get(entry_uuid=entry_uuid)
                username_field = User.USERNAME_FIELD
                if getattr(user, username_field) != username:
                    setattr(user, username_field, username)
                    user.save(update_fields=[username_field])
                return user, False  # ensure LDAP attributes still refresh
            except User.DoesNotExist:
                pass
        return super().get_or_build_user(username, ldap_user)


def search_by_entry_uuid(entry_uuid):
    connection = _get_ldap_connection()
    entry_uuid_attr = settings.AUTH_LDAP_USER_ATTR_MAP.get('entry_uuid', 'entryUUID')
    username_attr = getattr(settings, 'AUTH_LDAP_USERNAME_ATTR', 'uid')
    search = LDAPSearch(
        settings.AUTH_LDAP_USER_SEARCH.base_dn,
        settings.AUTH_LDAP_USER_SEARCH.scope,
        f'({entry_uuid_attr}=%(entry_uuid)s)',
        [username_attr, entry_uuid_attr],
    )
    return search.execute(connection, filterargs={'entry_uuid': entry_uuid})


def search_by_mail(mail):
    connection = _get_ldap_connection()
    mail_attr = settings.AUTH_LDAP_USER_ATTR_MAP['email']
    username_attr = getattr(settings, 'AUTH_LDAP_USERNAME_ATTR', 'uid')
    entry_uuid_attr = settings.AUTH_LDAP_USER_ATTR_MAP.get('entry_uuid', 'entryUUID')
    search = LDAPSearch(
        settings.AUTH_LDAP_USER_SEARCH.base_dn,
        settings.AUTH_LDAP_USER_SEARCH.scope,
        f'({mail_attr}=%(mail)s)',
        [username_attr, entry_uuid_attr],
    )
    return search.execute(connection, filterargs={'mail': mail})


def social_auth_link_user_via_ldap_entryuuid(backend, details: dict[str, Any], user=None, *_args, **_kwargs):
    """
    Enforce: social logins are only allowed for users that exist in LDAP.
    - Find LDAP entry by social email.
    - If not found -> deny login.
    - If found -> populate local User from LDAP (links by entryUUID via backend).
    - Return that user so PSA associates the social account with it.
    """
    ldap_backend = UUIDLinkingLDAPBackend()
    username_attr = getattr(settings, 'AUTH_LDAP_USERNAME_ATTR', 'uid')

    if user is None:
        mail = (details or {}).get('email')
        if not mail:
            raise AuthForbidden(backend)

        results = search_by_mail(mail)
        if not results or len(results) != 1:
            raise AuthForbidden(backend)

        _dn, attrs = results[0]
        uid = _get_attr(attrs, username_attr)
        if not uid:
            raise AuthForbidden(backend)
        linked = ldap_backend.populate_user(uid)
        if not linked:
            raise AuthForbidden(backend)
        return {'user': linked}

    entry_uuid = getattr(user, 'entry_uuid', None)
    if not entry_uuid:
        uid = getattr(user, User.USERNAME_FIELD)
        refreshed = ldap_backend.populate_user(uid)
        return {'user': refreshed or user}

    results = search_by_entry_uuid(entry_uuid)
    if results:
        _dn, attrs = results[0]
        uid = _get_attr(attrs, username_attr)
        if uid:
            refreshed = ldap_backend.populate_user(uid)
            return {'user': refreshed or user}

    raise AuthForbidden(backend)
