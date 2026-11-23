from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django_auth_ldap.backend import LDAPBackend, _LDAPUser
from django_auth_ldap.config import LDAPSearch
from social_core.exceptions import AuthPolicyError

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
    Link existing users by their immutable LDAP UUID to keep identity stable across username changes.
    Requires AUTH_LDAP_USER_ATTR_MAP['ldap_uuid'] and AUTH_LDAP_USER_SEARCH to request that attribute.
    """

    def get_or_build_user(self, username, ldap_user) -> tuple[User, bool]:
        ldap_uuid_attr = settings.AUTH_LDAP_USER_ATTR_MAP.get('ldap_uuid', 'entryUUID')
        ldap_uuid = _get_attr(ldap_user.attrs, ldap_uuid_attr)
        if ldap_uuid:
            try:
                user = User.objects.get(ldap_uuid=ldap_uuid)
                username_field = User.USERNAME_FIELD
                if getattr(user, username_field) != username:
                    setattr(user, username_field, username)
                    user.save(update_fields=[username_field])
                return user, False  # ensure LDAP attributes still refresh
            except User.DoesNotExist:
                pass
        return super().get_or_build_user(username, ldap_user)


def search_by_ldap_uuid(ldap_uuid):
    connection = _get_ldap_connection()
    ldap_uuid_attr = settings.AUTH_LDAP_USER_ATTR_MAP.get('ldap_uuid', 'entryUUID')
    username_attr = getattr(settings, 'AUTH_LDAP_USERNAME_ATTR', 'uid')
    search = LDAPSearch(
        settings.AUTH_LDAP_USER_SEARCH.base_dn,
        settings.AUTH_LDAP_USER_SEARCH.scope,
        f'({ldap_uuid_attr}=%(ldap_uuid)s)',
        [username_attr, ldap_uuid_attr],
    )
    return search.execute(connection, filterargs={'ldap_uuid': ldap_uuid})


def search_by_mail(mail):
    connection = _get_ldap_connection()
    mail_attr = settings.AUTH_LDAP_USER_ATTR_MAP['email']
    username_attr = getattr(settings, 'AUTH_LDAP_USERNAME_ATTR', 'uid')
    ldap_uuid_attr = settings.AUTH_LDAP_USER_ATTR_MAP.get('ldap_uuid', 'entryUUID')
    search = LDAPSearch(
        settings.AUTH_LDAP_USER_SEARCH.base_dn,
        settings.AUTH_LDAP_USER_SEARCH.scope,
        f'({mail_attr}=%(mail)s)',
        [username_attr, ldap_uuid_attr],
    )
    return search.execute(connection, filterargs={'mail': mail})


def social_auth_link_user_via_ldap_uuid(backend, details: dict[str, Any], user=None, *_args, **_kwargs):
    """
    Enforce: social logins are only allowed for users that exist in LDAP.
    - Find the LDAP entry by LDAP UUID for known users, by social email otherwise.
    - If not found -> deny login.
    - If found -> populate local User from LDAP (links by LDAP UUID via backend).
    - Return that user so PSA associates the social account with it.
    """
    username_attr = getattr(settings, 'AUTH_LDAP_USERNAME_ATTR', 'uid')
    username = None

    if user is None:
        mail = (details or {}).get('email')
        results = search_by_mail(mail) if mail else []
        if len(results) == 1:
            username = _get_attr(results[0][1], username_attr)
    elif ldap_uuid := getattr(user, 'ldap_uuid', None):
        results = search_by_ldap_uuid(ldap_uuid)
        if results:
            username = _get_attr(results[0][1], username_attr)
    else:
        username = getattr(user, User.USERNAME_FIELD)

    linked = UUIDLinkingLDAPBackend().populate_user(username) if username else None
    if not linked:
        raise AuthPolicyError(backend, stage='pipeline')
    return {'user': linked}
