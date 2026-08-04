"""Users router: pending-secrets (offboarding) sub-resource.

Users are addressed by their numeric id; usernames are never path identifiers in v2.
"""

import datetime

from django.contrib.auth import get_user_model
from django.db.models import Max
from ninja import Field, FilterSchema, Query, Router
from ninja.errors import HttpError
from ninja.pagination import paginate
from ninja.responses import codes_4xx

from teamvault.api.v2.listing import (
    PageNumberEnvelopePagination,
    PageTransform,
    reject_unknown_query_params,
)
from teamvault.api.v2.schemas import ErrorDetail, SecretRef
from teamvault.api.v2.scopes import requires_scope
from teamvault.api.v2.secrets.schemas import STATUS_REPR
from teamvault.apps.accounts.utils import get_pending_secrets_for_user

router = Router(tags=['users'])

User = get_user_model()


class PendingSecret(SecretRef):
    """A secret a user must rotate on leaving: it needs changing and the user has read it."""

    status: str = Field(
        description="Secret status, always 'needs_changing' for a pending secret.",
        examples=['needs_changing'],
    )
    web_url: str = Field(
        description='Absolute URL of the secret in the TeamVault web UI.',
        examples=['https://teamvault.example.com/secrets/k3mZpqR7/'],
    )
    last_changed_at: datetime.datetime = Field(
        description='When the secret was last changed (v1 `last_changed`).',
        examples=['2026-01-15T09:30:00Z'],
    )
    last_read_at: datetime.datetime = Field(
        description='When the secret was last read by anyone (v1 `last_read`).',
        examples=['2026-02-20T14:05:00Z'],
    )
    last_shared: datetime.datetime | None = Field(
        description="When the secret was most recently shared (max of its shares' `granted_on`); null if never.",
        examples=['2026-01-10T08:00:00Z'],
    )


class PendingSecretFilters(FilterSchema):
    model_config = {'extra': 'forbid'}

    q: str | None = Field(None, q='name__icontains', description='Case-insensitive substring match on the secret name.')


PENDING_LIST_QUERY_PARAMS = set(PendingSecretFilters.model_fields) | set(
    PageNumberEnvelopePagination.Input.model_fields
)


def _pending_secret(secret) -> PendingSecret:
    return PendingSecret(
        hashid=secret.hashid,
        name=secret.name,
        status=STATUS_REPR[secret.status],
        web_url=secret.full_url,
        last_changed_at=secret.last_changed,
        last_read_at=secret.last_read,
        last_shared=secret.last_shared,
    )


@router.get(
    '/{user_id}/pending-secrets',
    response={200: list[PendingSecret], codes_4xx: ErrorDetail},
    operation_id='list_user_pending_secrets',
    summary="List a user's pending secrets",
    description=(
        'Lists the secrets a user must rotate when they leave: secrets that need changing'
        ' (`status = needs_changing`, `needs_changing_on_leave = true`) whose current payload the user'
        ' has read at some point (access-history based, so current group membership is irrelevant). The'
        " v2 home of v1's `/api/users/<username>/pending-secrets/`, addressed by numeric user id.\n\n"
        '- **Required scope**: `users:read` — **and** the calling token must belong to a superuser'
        ' (this offboarding view exposes secrets across all users; the superuser gate is the v1-parity'
        ' authorization). A non-superuser token holder gets 403 even with the scope.\n'
        '- **Pagination**: `page`/`page_size` (default 50, max 200)\n'
        '- **Filters**: `q` (case-insensitive substring match on the secret name)\n'
        '- Returns 404 for an unknown user id.'
    ),
)
@paginate(PageNumberEnvelopePagination)
@requires_scope('users:read')
def list_user_pending_secrets(request, user_id: int, filters: Query[PendingSecretFilters]):
    # Deliberately authz-first (unlike the other list endpoints, which 422 unknown params first):
    # non-superusers learn nothing about this endpoint's parameters or which user ids exist.
    if not request.auth.user.is_superuser:
        raise HttpError(403, "Listing a user's pending secrets requires a superuser token.")

    reject_unknown_query_params(request, PENDING_LIST_QUERY_PARAMS)

    try:
        target = User.objects.get(pk=user_id)
    except User.DoesNotExist as exc:
        raise HttpError(404, f'No user with id {user_id}') from exc

    queryset = filters.filter(get_pending_secrets_for_user(target))
    queryset = queryset.annotate(last_shared=Max('share_data__granted_on')).order_by('name', 'hashid')
    return PageTransform(queryset, lambda page: [_pending_secret(secret) for secret in page])
