try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import SafeConfigParser
from os import environ
from sys import argv

from django.apps import AppConfig


class SettingsConfig(AppConfig):
    name = 'teamvault.apps.settings'

    def ready(self):
        if "makemigrations" in argv or "migrate" in argv:
            return

        from django.conf import settings
        from .utils import get_secret

        config = SafeConfigParser()
        config.read(environ['TEAMVAULT_CONFIG_FILE'])

        settings.TEAMVAULT_SECRET_KEY = get_secret(config)

        configure_ldap_auth(config, settings)


def configure_ldap_auth(config, settings):
    if not config.has_section("auth_ldap"):
        return

    from django_auth_ldap.config import LDAPSearch, MemberDNGroupType
    from ldap3 import SEARCH_SCOPE_WHOLE_SUBTREE

    settings.AUTHENTICATION_BACKENDS = (
        'django_auth_ldap.backend.LDAPBackend',
        'django.contrib.auth.backends.ModelBackend',
    )
    settings.AUTH_LDAP_SERVER_URI = config.get("auth_ldap", "server_uri")
    settings.AUTH_LDAP_BIND_DN = config.get("auth_ldap", "bind_dn")
    settings.AUTH_LDAP_BIND_PASSWORD = config.get("auth_ldap", "password")

    settings.AUTH_LDAP_USER_SEARCH = LDAPSearch(
        config.get("auth_ldap", "user_base_dn"),
        SEARCH_SCOPE_WHOLE_SUBTREE,
        config.get("auth_ldap", "user_search_filter", "(cn=%(user)s)"),
    )
    settings.AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
        config.get("auth_ldap", "group_base_dn"),
        SEARCH_SCOPE_WHOLE_SUBTREE,
        config.get("auth_ldap", "group_search_filter", "(objectClass=group)"),
    )

    settings.AUTH_LDAP_GROUP_TYPE = MemberDNGroupType('member')
    settings.AUTH_LDAP_REQUIRE_GROUP = config.get("auth_ldap", "require_group", None)

    settings.AUTH_LDAP_USER_ATTR_MAP = {
        "email": config.get("auth_ldap", "attr_email", "mail"),
        "first_name": config.get("auth_ldap", "attr_first_name", "givenName"),
        "last_name": config.get("auth_ldap", "attr_last_name", "sn"),
    }
    settings.AUTH_LDAP_USER_FLAGS_BY_GROUP = {
        "is_superuser": config.get("auth_ldap", "admin_group"),
    }

    settings.AUTH_LDAP_ALWAYS_UPDATE_USER = True
    settings.AUTH_LDAP_FIND_GROUP_PERMS = False
    settings.AUTH_LDAP_MIRROR_GROUPS = True
    settings.AUTH_LDAP_CACHE_GROUPS = True
    settings.AUTH_LDAP_GROUP_CACHE_TIMEOUT = 900
