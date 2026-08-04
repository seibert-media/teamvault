"""Shares sub-resource of secrets: list, create, delete.

Mounted under `/secrets/{hashid}/shares`. Lives in its own module to keep the secrets router
focused; it shares the `readable_secret` gate and listing machinery with that router.
"""

from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.utils.timezone import now
from django.utils.translation import gettext as _
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
from teamvault.api.v2.secrets.schemas import ShareCreateRequest, ShareSchema, build_share_schemas
from teamvault.apps.accounts.models import User
from teamvault.apps.audit.auditlog import log
from teamvault.apps.audit.models import AuditLogCategoryChoices
from teamvault.apps.secrets.models import AccessPermissionTypes, SharedSecretData

router = Router(tags=['secrets'])

SHARE_SORT_FIELDS = {'granted_at': 'granted_on'}
SHARE_EXPAND_FIELDS = {'user', 'group', 'granted_by'}


class ShareFilters(FilterSchema):
    model_config = {'extra': 'forbid'}

    user: int | None = Field(None, q='user_id', description='Numeric id of the user the share is granted to.')
    group: int | None = Field(None, q='group_id', description='Numeric id of the group the share is granted to.')
    is_expired: bool | None = Field(None, description='Filter on whether the share has expired.')

    # ninja calls these filter_<field> hooks as instance methods; the signature is fixed.
    def filter_is_expired(self, value: bool | None) -> Q:  # noqa: PLR6301
        if value is None:
            return Q()
        expired = Q(granted_until__lte=now())
        return expired if value else ~expired


SHARE_LIST_QUERY_PARAMS = (
    set(ShareFilters.model_fields) | set(PageNumberEnvelopePagination.Input.model_fields) | {'sort', 'expand'}
)


@router.get(
    '/{hashid}/shares',
    response={200: list[ShareSchema], codes_4xx: ErrorDetail},
    operation_id='list_secret_shares',
    summary="List a secret's shares",
    description=(
        'Lists the shares of a secret: who (a user or a group) has been granted access, by whom, and'
        ' until when. Each item carries a computed `is_expired`. Visibility follows the same gate as'
        ' `get_secret` (an invisible secret returns 404).\n\n'
        '- **Required scope**: `secrets:read`\n'
        '- **Pagination**: `page`/`page_size` (default 50, max 200)\n'
        '- **Filters**: `user`, `group`, `is_expired` (combine with AND)\n'
        f'- **Sort**: `?sort=key,-key2` with keys {", ".join(sorted(SHARE_SORT_FIELDS))} (default `-granted_at`)\n'
        f'- **Expand**: {", ".join(sorted(SHARE_EXPAND_FIELDS))} (one level deep)\n'
        '- **Related**: `create_secret_share`, `delete_secret_share`'
    ),
)
@paginate(PageNumberEnvelopePagination)
@requires_scope('secrets:read')
def list_secret_shares(
    request, hashid: str, filters: Query[ShareFilters], sort: str | None = None, expand: str | None = None
):
    reject_unknown_query_params(request, SHARE_LIST_QUERY_PARAMS)
    order_by = parse_sort(sort, SHARE_SORT_FIELDS, default=['-granted_on'])
    expanded = parse_expand(expand, SHARE_EXPAND_FIELDS)

    user = request.auth.user
    secret = readable_secret(user, hashid)
    queryset = filters.filter(secret.share_data.all()).select_related('user', 'group', 'granted_by')
    # Deterministic ordering with a pk tiebreaker so pagination is stable across requests.
    queryset = queryset.order_by(*order_by, 'pk')
    return PageTransform(queryset, lambda page: build_share_schemas(page, expanded))


def _shareable_secret(user, hashid: str):
    """Fetch a secret and enforce the user's share access (404 invisible, 403 not shareable)."""
    secret = readable_secret(user, hashid)
    try:
        secret.check_share_access(user)
    except PermissionDenied as exc:
        raise HttpError(403, 'You do not have permission to manage shares of this secret') from exc
    return secret


@router.post(
    '/{hashid}/shares',
    response={201: ShareSchema, 422: ErrorDetail, codes_4xx: ErrorDetail},
    operation_id='create_secret_share',
    summary='Share a secret with a user or group',
    description=(
        'Grants access to a secret to exactly one user or one group. Set exactly one of `user`/`group`'
        ' (both or neither is rejected with 422). An existing active share for the same user/group is'
        ' rejected (422); an expired share for the same target is replaced. Mirrors the legacy `/api/`'
        ' semantics, including audit logging (a dedicated superuser category when a superuser shares a'
        ' secret they only reach via superuser privileges).\n\n'
        '- **Required scope**: `shares:write` (never implied by `secrets:write`)\n'
        '- **Permissions**: you must have share access to the secret (otherwise 403)\n'
        '- **Related**: `list_secret_shares`, `delete_secret_share`'
    ),
)
@requires_scope('shares:write')
def create_secret_share(request, hashid: str, payload: ShareCreateRequest):
    user = request.auth.user
    secret = _shareable_secret(user, hashid)

    if (payload.user and payload.group) or (not payload.user and not payload.group):
        return 422, ErrorDetail(detail='Specify exactly one of user or group.')

    if payload.user is not None:
        target = User.objects.filter(pk=payload.user, is_active=True).first()
        if target is None:
            return 422, ErrorDetail(detail=f'No active user with id {payload.user}')
        entity_kwargs = {'user': target}
    else:
        target = Group.objects.filter(pk=payload.group).first()
        if target is None:
            return 422, ErrorDetail(detail=f'No group with id {payload.group}')
        entity_kwargs = {'group': target}

    active_share = secret.share_data.filter(**entity_kwargs).exclude(granted_until__lte=now())
    if active_share.exists():
        return 422, ErrorDetail(detail='This secret is already shared with that user or group.')

    share = secret.share(
        grant_description=payload.grant_description,
        granted_by=user,
        granted_until=payload.expires_at,
        **entity_kwargs,
    )
    share = SharedSecretData.objects.select_related('user', 'group', 'granted_by').get(pk=share.pk)
    return 201, build_share_schemas([share], frozenset())[0]


@router.delete(
    '/{hashid}/shares/{share_id}',
    response={204: None, codes_4xx: ErrorDetail},
    operation_id='delete_secret_share',
    summary='Remove a share',
    description=(
        'Removes a share, revoking the granted access. Returns 404 if the share does not belong to the'
        ' given secret. Mirrors the legacy `/api/` audit logging, including a dedicated superuser'
        ' category when a superuser removes a share via superuser privileges.\n\n'
        '- **Required scope**: `shares:write` (never implied by `secrets:write`)\n'
        '- **Permissions**: you must have share access to the secret (otherwise 403)\n'
        '- **Related**: `list_secret_shares`, `create_secret_share`'
    ),
)
@requires_scope('shares:write')
def delete_secret_share(request, hashid: str, share_id: int):
    user = request.auth.user
    secret = _shareable_secret(user, hashid)

    try:
        share = secret.share_data.get(pk=share_id)
    except SharedSecretData.DoesNotExist as exc:
        raise HttpError(404, f'No share with id {share_id} for this secret') from exc

    permission = share.check_delete_access(user)
    entity_type = share.shared_entity_type
    entity_name = share.shared_entity_name
    share.delete()

    log(
        _("{user} removed access of {shared_entity_type} '{name}'").format(
            shared_entity_type=entity_type,
            name=entity_name,
            user=user.username,
        ),
        actor=user,
        category=(
            AuditLogCategoryChoices.SECRET_SUPERUSER_SHARE_REMOVED
            if permission == AccessPermissionTypes.SUPERUSER_ALLOWED
            else AuditLogCategoryChoices.SECRET_SHARE_REMOVED
        ),
        level='warning',
        secret=secret,
    )
    return 204, None
