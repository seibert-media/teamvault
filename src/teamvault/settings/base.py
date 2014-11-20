from base64 import decodestring, encodestring
try:
    from ConfigParser import SafeConfigParser
except ImportError:
    from configparser import SafeConfigParser
from os import environ, umask
from os.path import dirname, exists, join, realpath
from random import choice
from string import ascii_letters, digits, punctuation

from cryptography.fernet import Fernet


PROJECT_ROOT = realpath(dirname(dirname(__file__)))

if not exists(environ['TEAMVAULT_CONFIG_FILE']):
    SECRET_KEY = "".join(choice(ascii_letters + digits + punctuation) for i in range(50))
    config = SafeConfigParser()
    config.add_section("django")
    config.set("django", "secret_key", encodestring(SECRET_KEY))
    config.add_section("teamvault")
    config.set("teamvault", "fernet_key", Fernet.generate_key())
    old_umask = umask(7)
    try:
        with open(environ['TEAMVAULT_CONFIG_FILE'], 'wb') as f:
            config.write(f)
    finally:
        umask(old_umask)
else:
    config = SafeConfigParser()
    config.read(environ['TEAMVAULT_CONFIG_FILE'])


### Django

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
)

FIXTURE_DIRS = (
    join(PROJECT_ROOT, "fixtures"),
)

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.formtools',
    'django.contrib.humanize',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_gravatar',
    'rest_framework',
    'teamvault.apps.accounts.AccountsConfig',
    'teamvault.apps.audit.AuditConfig',
    'teamvault.apps.secrets.SecretsConfig',
    'teamvault.apps.settings.SettingsConfig',
]

LANGUAGE_CODE = "en-us"

LOCALE_PATHS = (PROJECT_ROOT + "/locale",)

LOGIN_REDIRECT_URL = "/"
LOGIN_URL = 'accounts.login'
LOGOUT_URL = 'accounts.logout'

MEDIA_ROOT = realpath(dirname(dirname(dirname(PROJECT_ROOT)))) + "/uploads"
MEDIA_URL = "/uploads/"

MIDDLEWARE_CLASSES = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
)

ROOT_URLCONF = "teamvault.urls"

SECRET_KEY = decodestring(config.get("django", "secret_key").encode('utf-8'))

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'

SITE_ID = 1

STATIC_ROOT = realpath(dirname(dirname(PROJECT_ROOT))) + "/static"

# remember this is hardcoded in the error page templates (e.g. 500.html)
STATIC_URL = "/static/"

STATICFILES_DIRS = (
    join(PROJECT_ROOT, "static"),
)

TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

TEMPLATE_DIRS = (
    join(PROJECT_ROOT, "templates"),
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.csrf',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.request',
    'django.core.context_processors.static',
    'teamvault.apps.secrets.context_processors.access_request_count',
)

TEST_RUNNER = 'django.test.runner.DiscoverRunner'

TIME_ZONE = None

USE_I18N = True
USE_L10N = True
USE_THOUSAND_SEPARATOR = False
USE_TZ = True


### REST Framework

REST_FRAMEWORK = {
    'DEFAULT_MODEL_SERIALIZER_CLASS':
        'rest_framework.serializers.HyperlinkedModelSerializer',
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    )
}

### TeamVault

TEAMVAULT_SECRET_KEY = None
