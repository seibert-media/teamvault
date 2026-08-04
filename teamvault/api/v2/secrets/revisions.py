"""Revisions (history) sub-resource of secrets: list and detail (read-only).

Mounted under `/secrets/{hashid}/revisions`. A revision is a `SecretChange` row — the metadata
snapshot of a secret at a point in time, with a reference to the payload that was current then.
Decrypted payload content is not served here; it stays behind the `secrets:data:read`
`/revisions/{revision_hashid}/data` endpoint in the secrets router. Lives in its own module to keep
the secrets router focused; it shares the `readable_secret` gate and listing machinery.
"""

import datetime

from ninja import Field, FilterSchema, Query, Router
from ninja.errors import HttpError
from ninja.pagination import paginate
from ninja.responses import codes_4xx

from teamvault.api.v2.listing import (
    PageNumberEnvelopePagination,
    PageTransform,
    parse_expand,
    parse_sort,
    reject_unknown_query_params,
)
from teamvault.api.v2.schemas import ErrorDetail
from teamvault.api.v2.scopes import requires_scope
from teamvault.api.v2.secrets.access import readable_secret
from teamvault.api.v2.secrets.schemas import RevisionSchema, build_revision_schemas
from teamvault.apps.secrets.models import SecretChange

router = Router(tags=['secrets'])

REVISION_SORT_FIELDS = {'created_at': 'created'}
REVISION_EXPAND_FIELDS = {'actor'}

# Refs (actor, scrubbed_by, payload + its set_by, parent, restored_from) resolved in one query each.
REVISION_RELATED = ('actor', 'scrubbed_by', 'revision', 'revision__set_by', 'parent', 'restored_from')


class RevisionFilters(FilterSchema):
    model_config = {'extra': 'forbid'}

    actor: int | None = Field(None, q='actor_id', description='Numeric id of the user who made the change.')
    created_after: datetime.datetime | None = Field(
        None, q='created__gte', description='Only revisions created at or after this timestamp.'
    )
    created_before: datetime.datetime | None = Field(
        None, q='created__lte', description='Only revisions created at or before this timestamp.'
    )


REVISION_LIST_QUERY_PARAMS = (
    set(RevisionFilters.model_fields) | set(PageNumberEnvelopePagination.Input.model_fields) | {'sort', 'expand'}
)


@router.get(
    '/{hashid}/revisions',
    response={200: list[RevisionSchema], codes_4xx: ErrorDetail},
    operation_id='list_secret_revisions',
    summary="List a secret's revision history",
    description=(
        "Lists a secret's history as a chain of revisions (SecretChange rows), newest first. Each"
        ' revision carries the metadata snapshot at that point in time, the actor, a `parent_hashid`'
        ' linking to the previous revision, an optional `restored_from_hashid`, and a `payload`'
        ' reference. Payloads are deduplicated, so several revisions may share one `payload.hashid`.'
        ' Decrypted payload *content* is served separately by `get_secret_revision_data`'
        ' (`secrets:data:read`). Visibility follows the same gate as `get_secret` (an invisible'
        ' secret returns 404).\n\n'
        '- **Required scope**: `secrets:read`\n'
        '- **Pagination**: `page`/`page_size` (default 50, max 200)\n'
        '- **Filters**: `actor`, `created_after`, `created_before` (combine with AND)\n'
        f'- **Sort**: `?sort=key,-key2` with keys {", ".join(sorted(REVISION_SORT_FIELDS))} (default `-created_at`)\n'
        f'- **Expand**: {", ".join(sorted(REVISION_EXPAND_FIELDS))} (one level deep)\n'
        '- **Related**: `get_secret_revision`, `get_secret_revision_data`'
    ),
)
@paginate(PageNumberEnvelopePagination)
@requires_scope('secrets:read')
def list_secret_revisions(
    request, hashid: str, filters: Query[RevisionFilters], sort: str | None = None, expand: str | None = None
):
    reject_unknown_query_params(request, REVISION_LIST_QUERY_PARAMS)
    order_by = parse_sort(sort, REVISION_SORT_FIELDS, default=['-created'])
    expanded = parse_expand(expand, REVISION_EXPAND_FIELDS)

    user = request.auth.user
    secret = readable_secret(user, hashid)
    queryset = filters.filter(secret.changes.select_related(*REVISION_RELATED))
    # Deterministic ordering with a pk tiebreaker so pagination is stable across requests.
    queryset = queryset.order_by(*order_by, 'pk')
    return PageTransform(queryset, lambda page: build_revision_schemas(page, expanded))


@router.get(
    '/{hashid}/revisions/{revision_hashid}',
    response={200: RevisionSchema, codes_4xx: ErrorDetail},
    operation_id='get_secret_revision',
    summary='Read a single revision',
    description=(
        'Returns a single revision (a SecretChange) of a secret, identified by `revision_hashid`.'
        ' Returns 404 if the revision does not belong to the given secret. The shape matches an item'
        ' of `list_secret_revisions`. Decrypted payload content stays behind'
        ' `get_secret_revision_data` (`secrets:data:read`).\n\n'
        '- **Required scope**: `secrets:read`\n'
        f'- **Expand**: {", ".join(sorted(REVISION_EXPAND_FIELDS))} (one level deep)\n'
        '- **Related**: `list_secret_revisions`, `get_secret_revision_data`'
    ),
)
@requires_scope('secrets:read')
def get_secret_revision(request, hashid: str, revision_hashid: str, expand: str | None = None) -> RevisionSchema:
    reject_unknown_query_params(request, {'expand'})
    expanded = parse_expand(expand, REVISION_EXPAND_FIELDS)

    user = request.auth.user
    secret = readable_secret(user, hashid)
    try:
        change = SecretChange.objects.select_related(*REVISION_RELATED).get(hashid=revision_hashid, secret=secret)
    except SecretChange.DoesNotExist as exc:
        raise HttpError(404, f'No revision with hashid {revision_hashid} for this secret') from exc
    return build_revision_schemas([change], expanded)[0]
