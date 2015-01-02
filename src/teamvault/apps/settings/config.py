from base64 import decodestring, encodestring
from configparser import SafeConfigParser
from gettext import gettext as _
from hashlib import sha1
from os import environ, umask
from os.path import exists, isfile
from random import choice
from string import ascii_letters, digits, punctuation
from urllib.parse import urlparse

from cryptography.fernet import Fernet


def configure_base_url(config, settings):
    settings.BASE_URL = config.get("teamvault", "base_url")
    settings.ALLOWED_HOSTS = [urlparse(settings.BASE_URL).hostname]


def configure_database(config):
    """
    Called directly from the Django settings module.
    """
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2',
            'HOST': get_from_config(config, "database", "host", "localhost"),
            'NAME': get_from_config(config, "database", "name", "teamvault"),
            'PASSWORD': get_from_config(config, "database", "password", ""),
            'PORT': get_from_config(config, "database", "port", "5432"),
            'USER': get_from_config(config, "database", "user", "teamvault"),
        },
    }
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
        get_from_config(config, "auth_ldap", "user_search_filter", "(cn=%(user)s)"),
    )
    settings.AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
        config.get("auth_ldap", "group_base_dn"),
        SEARCH_SCOPE_WHOLE_SUBTREE,
        get_from_config(config, "auth_ldap", "group_search_filter", "(objectClass=group)"),
    )

    settings.AUTH_LDAP_GROUP_TYPE = MemberDNGroupType('member')
    settings.AUTH_LDAP_REQUIRE_GROUP = get_from_config(config, "auth_ldap", "require_group", None)

    settings.AUTH_LDAP_USER_ATTR_MAP = {
        "email": get_from_config(config, "auth_ldap", "attr_email", "mail"),
        "first_name": get_from_config(config, "auth_ldap", "attr_first_name", "givenName"),
        "last_name": get_from_config(config, "auth_ldap", "attr_last_name", "sn"),
    }
    settings.AUTH_LDAP_USER_FLAGS_BY_GROUP = {
        "is_staff": config.get("auth_ldap", "admin_group"),
        "is_superuser": config.get("auth_ldap", "admin_group"),
    }

    settings.AUTH_LDAP_ALWAYS_UPDATE_USER = True
    settings.AUTH_LDAP_FIND_GROUP_PERMS = False
    settings.AUTH_LDAP_MIRROR_GROUPS = True
    settings.AUTH_LDAP_CACHE_GROUPS = True
    settings.AUTH_LDAP_GROUP_CACHE_TIMEOUT = 900


def configure_max_file_size(config, settings):
    settings.TEAMVAULT_MAX_FILE_SIZE = int(
        get_from_config(config, "teamvault", "max_file_size", "5242880")
    )
    settings.FILE_UPLOAD_MAX_MEMORY_SIZE = settings.TEAMVAULT_MAX_FILE_SIZE


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
    if exists(filename):
        raise RuntimeError("not overwriting existing path {}".format(filename))
    SECRET_KEY = "".join(choice(ascii_letters + digits + punctuation) for i in range(50))
    config = """
[teamvault]
# Set this to the URL users use to reach the application
base_url = https://example.com
# This key has been generated for you, there is no need to change it
fernet_key = {teamvault_key}
# file uploads larger than this number of bytes will have their connection reset
max_file_size = 5242880

[django]
# This key has been generated for you, there is no need to change it
secret_key = {django_key}

[database]
host = localhost
name = teamvault
user = teamvault
password = teamvault

#[auth_ldap]
#server_uri = ldaps://ldap.example.com
#bind_dn = cn=root,dc=example,dc=com
#password = example
#user_base_dn = ou=users,dc=example,dc=com
##user_search_filter = (cn=%(user)s)
#group_base_dn = ou=groups,dc=example,dc=com
##group_search_filter = (objectClass=group)
##require_group = cn=employees,ou=groups,dc=example,dc=com
##attr_email = mail
##attr_first_name = givenName
##attr_last_name = sn
#admin_group = cn=admins,ou=groups,dc=example,dc=com
    """.format(
        django_key=encodestring(SECRET_KEY.encode('utf-8')).decode('utf-8'),
        teamvault_key=Fernet.generate_key().decode('utf-8'),
    )
    old_umask = umask(7)
    try:
        with open(filename, 'wt') as f:
            f.write(config.strip())
    finally:
        umask(old_umask)


def get_config():
    if not isfile(environ['TEAMVAULT_CONFIG_FILE']):
        raise RuntimeError(
            _("missing config file at {} "
              "(set env var TEAMVAULT_CONFIG_FILE to use a different path)").format(
                environ['TEAMVAULT_CONFIG_FILE'],
            )
        )

    with open(environ['TEAMVAULT_CONFIG_FILE']) as f:
        # SafeConfigParser.read() will not complain if it can't read the
        # file, so we need to read it once ourselves to get a proper IOError
        f.read()

    config = SafeConfigParser()
    config.read(environ['TEAMVAULT_CONFIG_FILE'])
    return config


def get_from_config(config, section, option, default):
    if config.has_option(section, option):
        return config.get(section, option)
    else:
        return default
