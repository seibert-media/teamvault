from base64 import b64decode, b64encode
from configparser import ConfigParser
from gettext import gettext as _
from hashlib import sha1
from os import environ, umask
from os.path import exists, isfile
from random import choice
from string import ascii_letters, digits, punctuation
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from django.db.utils import ProgrammingError


class UnconfiguredSettingsError(Exception):
    def __str__(self):
        return _(
            "missing config file at {} (set env var TEAMVAULT_CONFIG_FILE to use a different path)"
        ).format(environ['TEAMVAULT_CONFIG_FILE'])


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


def configure_debugging(config, settings):
    enabled = get_from_config(config, "teamvault", "insecure_debug_mode", "no")
    if enabled.lower() in ("1", "enabled", "true", "yes"):
        settings.DEBUG = True
        settings.EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    else:
        settings.DEBUG = False


def configure_django_secret_key(config):
    """
    Called directly from the Django settings module.
    """
    return b64decode(config.get("django", "secret_key").encode()).decode('utf-8')


def configure_hashid(config):
    """
    Called directly from the Django settings module.
    """
    return (
        int(get_from_config(config, "hashid", "min_length", "6")),
        b64decode(config.get("hashid", "salt").encode()).decode('utf-8'),
    )


def configure_google_auth(config, settings):
    if not config.has_section("auth_google"):
        settings.GOOGLE_AUTH_ENABLED = False
        return

    settings.GOOGLE_AUTH_ENABLED = True

    settings.AUTHENTICATION_BACKENDS.insert(
        0,
        'social_core.backends.google.GoogleOAuth2',
    )

    settings.SOCIAL_AUTH_PIPELINE = (
        # Get the information we can about the user and return it in a simple
        # format to create the user instance later. In some cases the details are
        # already part of the auth response from the provider, but sometimes this
        # could hit a provider API.
        'social_core.pipeline.social_auth.social_details',

        # Get the social uid from whichever service we're authing thru. The uid is
        # the unique identifier of the given user in the provider.
        'social_core.pipeline.social_auth.social_uid',

        # Verifies that the current auth process is valid within the current
        # project, this is where emails and domains whitelists are applied (if
        # defined).
        'social_core.pipeline.social_auth.auth_allowed',

        # Checks if the current social-account is already associated in the site.
        'social_core.pipeline.social_auth.social_user',

        # Associates the current social details with another user account with
        # a similar email address.
        'social_core.pipeline.social_auth.associate_by_email',

        # Create a user account if we haven't found one yet.
        'social_core.pipeline.user.create_user',

        # Create the record that associates the social account with the user.
        'social_core.pipeline.social_auth.associate_user',

        # Populate the extra_data field in the social record with the values
        # specified by settings (and the default ones like access_token, etc).
        'social_core.pipeline.social_auth.load_extra_data',

        # Update the user record with any changed info from the auth service.
        'social_core.pipeline.user.user_details',

        # Get groups from LDAP
        'teamvault.apps.accounts.auth.populate_from_ldap',
    )

    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = [
        domain.strip() for domain in
        config.get("auth_google", "allowed_domains").split(",")
    ]

    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = config.get("auth_google", "oauth2_key")
    settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = config.get("auth_google", "oauth2_secret")


def configure_ldap_auth(config, settings):
    if not config.has_section("auth_ldap"):
        settings.LDAP_AUTH_ENABLED = False
        return

    settings.LDAP_AUTH_ENABLED = True

    from django_auth_ldap.config import LDAPSearch, MemberDNGroupType
    from ldap import (
        SCOPE_SUBTREE,
        OPT_X_TLS_CERTFILE,
        OPT_X_TLS_KEYFILE,
        OPT_X_TLS_REQUIRE_CERT,
        OPT_X_TLS_NEVER,
        OPT_X_TLS_NEWCTX,
    )

    settings.AUTHENTICATION_BACKENDS.insert(
        0,
        'django_auth_ldap.backend.LDAPBackend',
    )
    settings.AUTH_LDAP_SERVER_URI = config.get("auth_ldap", "server_uri")
    settings.AUTH_LDAP_BIND_DN = config.get("auth_ldap", "bind_dn")
    settings.AUTH_LDAP_BIND_PASSWORD = config.get("auth_ldap", "password")

    settings.AUTH_LDAP_USER_SEARCH = LDAPSearch(
        config.get("auth_ldap", "user_base_dn"),
        SCOPE_SUBTREE,
        get_from_config(config, "auth_ldap", "user_search_filter", "(cn=%(user)s)"),
    )
    settings.AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
        config.get("auth_ldap", "group_base_dn"),
        SCOPE_SUBTREE,
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

    settings.AUTH_LDAP_CONNECTION_OPTIONS = {}
    settings.AUTH_LDAP_GLOBAL_OPTIONS = {}

    if get_from_config(config, "auth_ldap", "start_tls", "no").lower() in \
            ("1", "enabled", "true", "yes"):
        settings.AUTH_LDAP_START_TLS = True

    if get_from_config(config, "auth_ldap", "client_cert", None):
        settings.AUTH_LDAP_CONNECTION_OPTIONS[OPT_X_TLS_CERTFILE] = \
            config.get("auth_ldap", "client_cert")
        settings.AUTH_LDAP_CONNECTION_OPTIONS[OPT_X_TLS_KEYFILE] = \
            config.get("auth_ldap", "client_key")

    if get_from_config(config, "auth_ldap", "disable_server_cert_validation", "no").lower() in \
            ("1", "enabled", "true", "yes"):
        settings.AUTH_LDAP_CONNECTION_OPTIONS[OPT_X_TLS_REQUIRE_CERT] = \
            OPT_X_TLS_NEVER
        # must be set last, relies on dict insertion order
        settings.AUTH_LDAP_CONNECTION_OPTIONS[OPT_X_TLS_NEWCTX] = 0


def configure_logging(config):
    level = 'INFO'

    if get_from_config(config, "teamvault", "insecure_debug_mode", "no").lower() in \
        ("1", "enabled", "true", "yes"):
        level = 'DEBUG'

    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'console': {
                'format': "[%(asctime)s] %(levelname)s %(module)s: %(message)s",
            },
        },
        'handlers': {
            'console': {
                'formatter': 'console',
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
            },
        },
        'loggers': {
            'django': {
                'handlers': ['console'],
                'level': level,
            },
            'django_auth_ldap': {
                'handlers': ['console'],
                'level': level,
            },
            'teamvault': {
                'handlers': ['console'],
                'level': level,
            },
        },
    }

    return LOGGING


def configure_max_file_size(config, settings):
    settings.TEAMVAULT_MAX_FILE_SIZE = int(
        get_from_config(config, "teamvault", "max_file_size", "5242880")
    )
    settings.FILE_UPLOAD_MAX_MEMORY_SIZE = settings.TEAMVAULT_MAX_FILE_SIZE


def configure_session(config):
    """
    Called directly from the Django settings module.
    """
    age = int(get_from_config(config, "teamvault", "session_cookie_age", "3600"))
    expire = get_from_config(config, "teamvault", "session_expire_at_browser_close", "True")
    secure = get_from_config(config, "teamvault", "session_cookie_secure", "False")

    if age <= 0:
        age = 3600
    expire = expire.lower() in ("1", "enabled", "true", "yes")
    secure = secure.lower() in ("1", "enabled", "true", "yes")

    return age, expire, secure


def configure_teamvault_secret_key(config, settings):
    from .models import Setting

    key = config.get("teamvault", "fernet_key")

    try:
        checksum = Setting.get("fernet_key_hash", default=None)
    except ProgrammingError:  # db not populated
        pass
    else:
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


def configure_time_zone(config):
    return get_from_config(config, "teamvault", "time_zone", "UTC")


def create_default_config(filename):
    if exists(filename):
        raise RuntimeError("not overwriting existing path {}".format(filename))
    SECRET_KEY = "".join(choice(ascii_letters + digits + punctuation) for i in range(50))
    HASHID_SALT = "".join(choice(ascii_letters + digits + punctuation) for i in range(50))
    config = """
[teamvault]
# Set this to the URL users use to reach the application
base_url = https://example.com
# This key has been generated for you, there is no need to change it
fernet_key = {teamvault_key}
# do not enable this in production
insecure_debug_mode = disabled
# file uploads larger than this number of bytes will have their connection reset
max_file_size = 5242880
session_cookie_age = 3600
session_expire_at_browser_close = True
session_cookie_secure = False
time_zone = UTC

[django]
# This key has been generated for you, there is no need to change it
secret_key = {django_key}

[database]
host = localhost
name = teamvault
user = teamvault
password = teamvault

[hashid]
min_length = 6
# This salt has been generated for you, there is no need to change it
salt = {hashid_salt}

#[auth_ldap]
#server_uri = ldaps://ldap.example.com
##start_tls = yes
##client_cert = /path/to/cert.crt
##client_key = /path/to/key.key
##disable_server_cert_validation = no
#bind_dn = cn=root,dc=example,dc=com
#password = ******************
#user_base_dn = ou=users,dc=example,dc=com
##user_search_filter = (cn=%%(user)s)
#group_base_dn = ou=groups,dc=example,dc=com
##group_search_filter = (objectClass=group)
##require_group = cn=employees,ou=groups,dc=example,dc=com
##attr_email = mail
##attr_first_name = givenName
##attr_last_name = sn
#admin_group = cn=admins,ou=groups,dc=example,dc=com

#[auth_google]
#allowed_domains = example.com, another.example.com
#oauth2_key = 123456789.apps.googleusercontent.com
#oauth2_secret = ******************
    """.format(
        django_key=b64encode(SECRET_KEY.encode('utf-8')).decode('utf-8'),
        hashid_salt=b64encode(HASHID_SALT.encode('utf-8')).decode('utf-8'),
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
        raise UnconfiguredSettingsError()

    with open(environ['TEAMVAULT_CONFIG_FILE']) as f:
        # ConfigParser.read() will not complain if it can't read the
        # file, so we need to read it once ourselves to get a proper IOError
        f.read()

    config = ConfigParser()
    config.read(environ['TEAMVAULT_CONFIG_FILE'])
    return config


def get_from_config(config, section, option, default):
    if config.has_option(section, option):
        return config.get(section, option)
    else:
        return default
