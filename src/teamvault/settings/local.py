from .base import *

ALLOWED_HOSTS = [
    "127.0.0.1",
]

BASE_URL = "http://127.0.0.1:8000"

DEPLOYMENT = 'local'

DEBUG = True
TEMPLATE_DEBUG = DEBUG

INTERNAL_IPS = ('127.0.0.1',)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
        'teamvault': {
            'handlers': ['console'],
            'level': 'DEBUG',
        }
    }
}

MEDIA_ROOT = realpath(dirname(dirname(PROJECT_ROOT))) + "/uploads"

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': realpath(dirname(dirname(PROJECT_ROOT))) + '/devdb.sqlite'
    }
}
