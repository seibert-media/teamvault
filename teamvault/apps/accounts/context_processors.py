from django.conf import settings


def google_auth_enabled(_request):
    return {'google_auth_enabled': settings.GOOGLE_AUTH_ENABLED}
