from http import HTTPStatus
from typing import TYPE_CHECKING

from django.contrib import messages
from django_htmx.http import trigger_client_event

if TYPE_CHECKING:
    from django.contrib.messages.storage.base import BaseStorage, Message


V1_API_PREFIX = '/api/'
V2_API_PREFIX = '/api/v2/'
# RFC 8594: a root-relative deprecation link is permitted; we keep it relative so it resolves
# regardless of host/scheme. No removal date is announced — v1 is frozen but supported.
DEPRECATION_LINK = '</api/v2/MIGRATION.md>; rel="deprecation"'


def v1_deprecation_headers_middleware(get_response):
    """Tag every legacy DRF (v1) response as deprecated per RFC 8594.

    Scoped to the `/api/` prefix but excluding `/api/v2/`, so the ninja v2 surface stays clean.
    v1 response bodies and status codes are untouched.
    """

    def middleware(request):
        response = get_response(request)
        path = request.path
        if path.startswith(V1_API_PREFIX) and not path.startswith(V2_API_PREFIX):
            response.headers['Deprecation'] = 'true'
            response.headers['Link'] = DEPRECATION_LINK
        return response

    return middleware


def htmx_message_middleware(get_response):
    # One-time configuration and initialization.

    def middleware(request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        response = get_response(request)

        # Ignore non-HTMX requests
        if 'HX-Request' not in request.headers:
            return response

        # HTMX will not read HX headers in redirects but the subsequent GET response.
        if HTTPStatus.MULTIPLE_CHOICES <= response.status_code < HTTPStatus.BAD_REQUEST:
            return response

        storage: BaseStorage = messages.get_messages(request)
        msg_list = []
        for msg in storage:
            msg: Message
            msg_list.append({
                'message': msg.message,
                # debug|info|success|warning|error
                'level': msg.level_tag,
            })

        trigger_client_event(response, 'django.contrib.messages', {'message_list': msg_list})
        return response

    return middleware
