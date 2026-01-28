from http import HTTPStatus
from typing import TYPE_CHECKING

from django.contrib import messages
from django_htmx.http import trigger_client_event

if TYPE_CHECKING:
    from django.contrib.messages.storage.base import BaseStorage, Message


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
