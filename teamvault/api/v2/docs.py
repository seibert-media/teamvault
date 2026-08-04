from typing import Any

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from ninja import NinjaAPI
from ninja.openapi.docs import DocsBase


class ElementsDocs(DocsBase):
    """Docs viewer using the vendored Stoplight Elements bundle instead of Swagger UI."""

    def render_page(self, request: HttpRequest, api: NinjaAPI, **kwargs: Any) -> HttpResponse:
        context = {'api': api, 'openapi_json_url': self.get_openapi_url(api, kwargs)}
        return render(request, 'api/v2/docs.html', context)
