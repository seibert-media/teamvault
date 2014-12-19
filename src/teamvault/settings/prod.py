from .base import *


DEPLOYMENT = 'prod'

DEBUG = False
TEMPLATE_DEBUG = DEBUG

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'teamvault': {
            'handlers': ['console'],
            'level': 'INFO',
        }
    }
}

STATIC_ROOT = realpath(PROJECT_ROOT) + "/static"
