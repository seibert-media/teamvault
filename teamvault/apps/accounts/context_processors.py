from django.conf import settings


def google_auth_enabled(request):  # noqa: ARG001
    return {'google_auth_enabled': settings.GOOGLE_AUTH_ENABLED}
