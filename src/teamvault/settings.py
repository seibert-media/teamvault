from os.path import dirname, join, realpath

from .apps.settings.config import (
    configure_database,
    configure_django_secret_key,
    configure_hashid,
    configure_logging,
    configure_session,
    get_config,
)

CONFIG = get_config()
PROJECT_ROOT = realpath(dirname(__file__))

### Django

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
)

DATABASES = configure_database(CONFIG)

FILE_UPLOAD_HANDLERS = (
    "teamvault.apps.secrets.utils.CappedMemoryFileUploadHandler",
)

FIXTURE_DIRS = (
    join(PROJECT_ROOT, "fixtures"),
)

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
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

LOGGING = configure_logging(CONFIG)

MIDDLEWARE_CLASSES = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
)

ROOT_URLCONF = "teamvault.urls"

SECRET_KEY = configure_django_secret_key(CONFIG)

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
SESSION_COOKIE_AGE, SESSION_EXPIRE_AT_BROWSER_CLOSE, SESSION_COOKIE_SECURE = \
    configure_session(CONFIG)

STATIC_ROOT = join(PROJECT_ROOT, "static_collected")

# remember this is hardcoded in the error page templates (e.g. 500.html)
STATIC_URL = "/static/"

STATICFILES_DIRS = (
    join(PROJECT_ROOT, "static"),
)

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [join(PROJECT_ROOT, "templates"),],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.csrf',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.request',
                'django.template.context_processors.static',
                'teamvault.apps.secrets.context_processors.access_request_count',
                'teamvault.apps.secrets.context_processors.version',
            ],
        },
    },
]

TEST_RUNNER = 'django.test.runner.DiscoverRunner'

TIME_ZONE = None

USE_I18N = False
USE_L10N = True
USE_THOUSAND_SEPARATOR = False
USE_TZ = True

### Hashid

HASHID_MIN_LENGTH, HASHID_SALT = configure_hashid(CONFIG)

### REST Framework

REST_FRAMEWORK = {
    'DEFAULT_MODEL_SERIALIZER_CLASS':
        'rest_framework.serializers.HyperlinkedModelSerializer',
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    )
}
