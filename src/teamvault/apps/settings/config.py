from base64 import decodestring, encodestring
from configparser import SafeConfigParser
from hashlib import sha1
from os import environ, umask
from random import choice
from string import ascii_letters, digits, punctuation
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from django.utils.translation import ugettext as _


DATABASE_ENGINES = {
    "mysql": 'django.db.backends.mysql',
    "oracle": 'django.db.backends.oracle',
    "postgres": 'django.db.backends.postgresql_psycopg2',
    "sqlite": 'django.db.backends.sqlite3',
}

CONFIG = SafeConfigParser()
CONFIG.read(environ['TEAMVAULT_CONFIG_FILE'])


def configure_base_url(config, settings):
    settings.BASE_URL = config.get("teamvault", "base_url")
    settings.ALLOWED_HOSTS = [urlparse(settings.BASE_URL).hostname]


def configure_database(config):
    """
    Called directly from the Django settings module.
    """
    DATABASES = {
        'default': {
            'ENGINE': DATABASE_ENGINES[get_from_config(config, "database", "engine", "postgres")],
            'HOST': get_from_config(config, "database", "host", "localhost"),
            'NAME': get_from_config(config, "database", "name", "teamvault"),
            'PASSWORD': get_from_config(config, "database", "password", ""),
            'USER': get_from_config(config, "database", "user", "teamvault"),
        },
    }
    if config.has_option("database", "port"):
        DATABASES['default']['PORT'] = config.get("database", "port")
    return DATABASES


def configure_django_secret_key(config):
    """
    Called directly from the Django settings module.
    """
    return decodestring(config.get("django", "secret_key").encode()).decode('utf-8')


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


def get_from_config(config, section, option, default):
    if config.has_option(section, option):
        return config.get(section, option)
    else:
        return default


def configure_teamvault_secret_key(config, settings):
    from .models import Setting

    checksum = Setting.get("fernet_key_hash", default=None)
    key = config.get("teamvault", "fernet_key")
    key_hash = sha1(key.encode('utf-8')).hexdigest()

    if checksum is None:
        Setting.set("fernet_key_hash", key_hash)

    elif key_hash != checksum:
        raise RuntimeError(_(
            "secret in '{path}' does not match SHA1 hash in database ({hash})"
        ).format(
            hash=checksum,
            path=environ['TEAMVAULT_CONFIG_FILE'],
        ))

    settings.TEAMVAULT_SECRET_KEY = key


def create_default_config(filename):
    SECRET_KEY = "".join(choice(ascii_letters + digits + punctuation) for i in range(50))
    config = SafeConfigParser()
    config.add_section("django")
    config.set("django", "secret_key", encodestring(SECRET_KEY.encode('utf-8')).decode('utf-8'))
    config.add_section("teamvault")
    config.set("teamvault", "fernet_key", Fernet.generate_key().decode('utf-8'))
    old_umask = umask(7)
    try:
        with open(filename, 'wt') as f:
            config.write(f)
    finally:
        umask(old_umask)
