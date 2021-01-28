from os import environ

from django.core.wsgi import get_wsgi_application


environ.setdefault("DJANGO_SETTINGS_MODULE", "teamvault.settings")
environ.setdefault("TEAMVAULT_CONFIG_FILE", "/etc/teamvault.cfg")

application = get_wsgi_application()
