"""Shared machinery for v2 list endpoints: pagination envelope, sorting, expand, strict query params."""

from collections.abc import Iterable, Mapping
from typing import Any

from django.http import HttpRequest
from ninja import Field, Schema
from ninja.errors import HttpError
from ninja.pagination import PaginationBase
from pydantic import ConfigDict

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def parse_sort(sort: str | None, allowed: Mapping[str, str], default: list[str]) -> list[str]:
    """Translate a `?sort=key,-key2` value into order_by() arguments via the per-resource allowlist.

    The result must always be applied explicitly (with a deterministic tiebreaker) before slicing,
    so pagination is stable across requests.
    """
    if not sort:
        return list(default)
    order_by = []
    for raw_key in sort.split(','):
        key = raw_key.removeprefix('-')
        if key not in allowed:
            raise HttpError(422, f'Unknown sort key: {key!r}. Allowed: {", ".join(sorted(allowed))}')
        order_by.append(('-' if raw_key.startswith('-') else '') + allowed[key])
    return order_by


def parse_expand(expand: str | None, allowed: Iterable[str]) -> set[str]:
    """Translate a `?expand=a,b` value into the set of fields to expand via the per-resource allowlist."""
    if not expand:
        return set()
    requested = {key for key in expand.split(',') if key}
    unknown = sorted(requested - set(allowed))
    if unknown:
        raise HttpError(
            422,
            f'Unknown expand value(s): {", ".join(unknown)}. Allowed: {", ".join(sorted(allowed))}',
        )
    return requested


def reject_unknown_query_params(request: HttpRequest, allowed: Iterable[str]) -> None:
    """422 on unknown query parameters.

    django-ninja silently drops query params that no handler argument declares (even with
    extra='forbid' schemas), so misspelled filters would otherwise be ignored. Call this
    first in every handler that takes query params.
    """
    allowed = set(allowed)
    unknown = sorted(set(request.GET) - allowed)
    if unknown:
        raise HttpError(
            422,
            f'Unknown query parameter(s): {", ".join(unknown)}. Allowed: {", ".join(sorted(allowed))}',
        )


class PageTransform:
    """Pairs a queryset with a transform the paginator applies to the sliced page.

    Lets a list view post-process only the items that end up on the page (e.g. `?expand=`
    resolution and ref building), once per page, so related objects resolve with bulk
    queries instead of per-row lookups.
    """

    def __init__(self, queryset, transform):
        self.queryset = queryset
        self.transform = transform


class PageNumberEnvelopePagination(PaginationBase):
    """DRF-style page+size pagination with a {count, next, previous, results} envelope."""

    items_attribute = 'results'

    class Input(Schema):
        page: int = Field(1, ge=1, description='1-based page number.', examples=[1])
        page_size: int = Field(
            DEFAULT_PAGE_SIZE,
            ge=1,
            description=f'Items per page. Values above {MAX_PAGE_SIZE} are silently clamped to {MAX_PAGE_SIZE}.',
            examples=[50],
        )

    class Output(Schema):
        # ninja's make_response_paginated() subclasses this schema and redeclares `results`
        # with a bare annotation, which drops the Field description below. The inherited
        # json_schema_extra hook restores it on every generated Paged* schema.
        model_config = ConfigDict(
            json_schema_extra=lambda schema, model: (  # noqa: ARG005
                schema.get('properties', {}).get('results', {}).setdefault('description', 'The items on this page.')
            )
        )

        count: int = Field(description='Total number of items across all pages.', examples=[123])
        next: str | None = Field(
            description='Absolute URL of the next page, or null on the last page.',
            examples=['https://teamvault.example.com/api/v2/secrets/?page=3'],
        )
        previous: str | None = Field(
            description='Absolute URL of the previous page, or null on the first page.',
            examples=['https://teamvault.example.com/api/v2/secrets/?page=1'],
        )
        results: list[Any] = Field(description='The items on this page.')

    def paginate_queryset(self, queryset, pagination: Input, request: HttpRequest = None, **params) -> dict:  # noqa: ARG002
        transform = None
        if isinstance(queryset, PageTransform):
            queryset, transform = queryset.queryset, queryset.transform
        page = pagination.page
        page_size = min(pagination.page_size, MAX_PAGE_SIZE)
        offset = (page - 1) * page_size
        count = self._items_count(queryset)

        def page_url(page_number: int) -> str:
            query = request.GET.copy()
            query['page'] = page_number
            return request.build_absolute_uri(f'{request.path}?{query.urlencode()}')

        results = queryset[offset : offset + page_size]
        if transform is not None:
            results = transform(list(results))
        return {
            'count': count,
            'next': page_url(page + 1) if offset + page_size < count else None,
            'previous': page_url(page - 1) if page > 1 else None,
            'results': results,
        }
