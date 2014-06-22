from os import environ
from os.path import dirname, join, realpath

PROJECT_ROOT = realpath(dirname(dirname(__file__)))

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
    'south',
    'sheldon.apps.secrets',
]

LANGUAGE_CODE = "en-us"

LOCALE_PATHS = (PROJECT_ROOT + "/locale",)

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

ROOT_URLCONF = "sheldon.urls"

SECRET_KEY = "FIXME"

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
    join(PROJECT_ROOT, "templates")
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.csrf',
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.core.context_processors.request',
    'django.core.context_processors.static',
    'django.contrib.messages.context_processors.messages',
)

USE_I18N = True
USE_L10N = True
USE_THOUSAND_SEPARATOR = False

# sheldon

environ.setdefault("SHELDON_SECRET_FILE", "/var/lib/sheldon/secret")

SHELDON_SECRET_FILE = environ["SHELDON_SECRET_FILE"]
SHELDON_SECRET = "UolYLuSBSabldUuR7KO9W0YagBx9QGaOR4kE3oxlUMA="
