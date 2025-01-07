from os.path import dirname, join, realpath

from huey import SqliteHuey

from teamvault.apps.settings.config import (
    configure_database,
    configure_django_secret_key,
    configure_hashid,
    configure_huey,
    configure_logging,
    configure_password_generator,
    configure_session,
    configure_time_zone,
    get_config,
    get_from_config,
)

CONFIG = get_config()
PROJECT_ROOT = realpath(dirname(__file__))

# Django

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]

DATABASES = configure_database(CONFIG)

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

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
    'django_bootstrap5',
    'huey.contrib.djhuey',
    'rest_framework',
    'social_django',
    'teamvault.apps.accounts.AccountsConfig',
    'teamvault.apps.audit.AuditConfig',
    'teamvault.apps.secrets.SecretsConfig',
    'teamvault.apps.settings.SettingsConfig',
    'webpack_loader',
]

LANGUAGE_CODE = "en-us"

LOCALE_PATHS = (PROJECT_ROOT + "/locale",)

LOGIN_REDIRECT_URL = "/"
LOGIN_URL = 'accounts.login'
LOGOUT_URL = 'accounts.logout'

LOGGING = configure_logging(CONFIG)

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'teamvault.middleware.htmx_message_middleware',
]

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
        'DIRS': [join(PROJECT_ROOT, "templates"), ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.csrf',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.request',
                'django.template.context_processors.static',
                'teamvault.apps.accounts.context_processors.google_auth_enabled',
                'teamvault.apps.secrets.context_processors.version',
            ],
        },
    },
]

TEST_RUNNER = 'django.test.runner.DiscoverRunner'

TIME_ZONE = configure_time_zone(CONFIG)

USE_I18N = False
USE_THOUSAND_SEPARATOR = False
USE_TZ = True

# HashID
HASHID_MIN_LENGTH, HASHID_SALT = configure_hashid(CONFIG)

# Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_MODEL_SERIALIZER_CLASS':
        'rest_framework.serializers.HyperlinkedModelSerializer',
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'PAGE_SIZE': 25,
}

# Social Auth
SOCIAL_AUTH_JSONFIELD_ENABLED = True

# Django-Bootstrap5
BOOTSTRAP5 = {
    'horizontal_field_class': 'col-xl-8',
    'horizontal_label_class': 'col-xl-2',
    'required_css_class': 'required',
    'success_css_class': 'is-valid',
    'error_css_class': 'is-invalid',
}

HUEY = SqliteHuey('teamvault')
HUEY_TASKS = configure_huey(CONFIG)
