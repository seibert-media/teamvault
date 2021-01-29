from django_auth_ldap.backend import LDAPBackend
from django.conf import settings


def populate_from_ldap(*args, **kwargs):
    if settings.LDAP_AUTH_ENABLED:
        LDAPBackend().populate_user(kwargs['user'].username)
