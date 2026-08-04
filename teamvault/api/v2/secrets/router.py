from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Q
from django.http import Http404
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
from teamvault.api.v2.secrets.access import readable_secret, writable_secret
from teamvault.api.v2.secrets.schemas import (
    CONTENT_TYPE_REPR,
    REPR_ACCESS_POLICY,
    REPR_CONTENT_TYPE,
    REPR_STATUS,
    CreditCardPayload,
    FilePayload,
    OtpToken,
    PasswordPayload,
    PayloadValidationError,
    SecretCreateRequest,
    SecretSchema,
    SecretUpdateRequest,
    build_secret_schema,
    build_secret_schemas,
    normalize_payload,
    serialize_payload,
)
from teamvault.apps.secrets.enums import ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret, SecretChange
from teamvault.apps.secrets.services.revision import RevisionService

router = Router(tags=['secrets'])

SECRET_SORT_FIELDS = {
    'name': 'name',
    'created_at': 'created',
    'last_changed_at': 'last_changed',
    'last_read_at': 'last_read',
}
SECRET_EXPAND_FIELDS = {'created_by'}


def _enum_or_422(value: str, mapping: dict, label: str):
    try:
        return mapping[value]
    except KeyError as exc:
        raise HttpError(422, f'Unknown {label}: {value!r}. Allowed: {", ".join(sorted(mapping))}') from exc


class SecretFilters(FilterSchema):
    model_config = {'extra': 'forbid'}

    q: str | None = Field(None, description='Full-text/substring search across the secrets visible to you.')
    status: str | None = Field(None, description="Exact match on status ('ok', 'needs_changing', 'deleted').")
    content_type: str | None = Field(
        None, description="Exact match on content type ('password', 'credit_card', 'file')."
    )
    access_policy: str | None = Field(
        None, description="Exact match on access policy ('any', 'discoverable', 'hidden')."
    )
    name: str | None = Field(None, q='name__icontains', description='Case-insensitive substring match on the name.')
    username: str | None = Field(
        None, q='username__icontains', description='Case-insensitive substring match on the username.'
    )
    created_by: int | None = Field(
        None, q='created_by_id', description='Numeric id of the user who created the secret.'
    )

    # ninja calls these filter_<field> hooks as instance methods; the signature is fixed.
    def filter_q(self, value: str | None) -> Q:  # noqa: ARG002, PLR6301
        return Q()  # resolved in the view via the search index

    def filter_status(self, value: str | None) -> Q:  # noqa: PLR6301
        if value is None:
            return Q()
        return Q(status=_enum_or_422(value, REPR_STATUS, 'status'))

    def filter_content_type(self, value: str | None) -> Q:  # noqa: PLR6301
        if value is None:
            return Q()
        return Q(content_type=_enum_or_422(value, REPR_CONTENT_TYPE, 'content_type'))

    def filter_access_policy(self, value: str | None) -> Q:  # noqa: PLR6301
        if value is None:
            return Q()
        return Q(access_policy=_enum_or_422(value, REPR_ACCESS_POLICY, 'access_policy'))


SECRET_LIST_QUERY_PARAMS = (
    set(SecretFilters.model_fields) | set(PageNumberEnvelopePagination.Input.model_fields) | {'sort', 'expand'}
)


def _with_refs(queryset):
    """Select the related rows the schema builder needs so refs resolve without per-row queries."""
    return queryset.select_related('created_by', 'current_revision', 'current_revision__set_by')


@router.get(
    '/',
    response={200: list[SecretSchema], codes_4xx: ErrorDetail},
    operation_id='list_secrets',
    summary='List secrets',
    description=(
        'Lists the secrets visible to you (same visibility as the legacy `/api/`): access policy'
        ' `any` and `discoverable` secrets, plus any shared directly with you; deleted secrets are'
        ' excluded. Each item carries `data_readable`, telling you whether you may decrypt it.\n\n'
        '- **Required scope**: `secrets:read`\n'
        '- **Pagination**: `page`/`page_size` (default 50, max 200)\n'
        '- **Filters**: `q`, `status`, `content_type`, `access_policy`, `name`, `username`, `created_by`'
        ' (combine with AND)\n'
        f'- **Sort**: `?sort=key,-key2` with keys {", ".join(sorted(SECRET_SORT_FIELDS))} (default `name`)\n'
        f'- **Expand**: {", ".join(sorted(SECRET_EXPAND_FIELDS))} (one level deep)\n'
        '- **Related**: `get_secret`'
    ),
)
@paginate(PageNumberEnvelopePagination)
@requires_scope('secrets:read')
def list_secrets(request, filters: Query[SecretFilters], sort: str | None = None, expand: str | None = None):
    reject_unknown_query_params(request, SECRET_LIST_QUERY_PARAMS)
    order_by = parse_sort(sort, SECRET_SORT_FIELDS, default=['name'])
    expanded = parse_expand(expand, SECRET_EXPAND_FIELDS)

    user = request.auth.user
    base = Secret.get_search_results(user, filters.q) if filters.q else Secret.get_all_visible_to_user(user)
    queryset = filters.filter(base)
    # Deterministic ordering with a hashid tiebreaker so pagination is stable across requests.
    queryset = _with_refs(queryset).order_by(*order_by, 'hashid')
    return PageTransform(queryset, lambda page: build_secret_schemas(user, page, expanded))


@router.get(
    '/{hashid}',
    response={200: SecretSchema, codes_4xx: ErrorDetail},
    operation_id='get_secret',
    summary='Get a secret',
    description=(
        'Returns a single secret by its `hashid`. Enforces the same access rules as the legacy `/api/`:'
        ' an invisible secret returns 404, a visible-but-unreadable secret returns 403.\n\n'
        '- **Required scope**: `secrets:read`\n'
        f'- **Expand**: {", ".join(sorted(SECRET_EXPAND_FIELDS))} (one level deep)\n'
        '- **Related**: `list_secrets`'
    ),
)
@requires_scope('secrets:read')
def get_secret(request, hashid: str, expand: str | None = None):
    reject_unknown_query_params(request, {'expand'})
    expanded = parse_expand(expand, SECRET_EXPAND_FIELDS)

    user = request.auth.user
    try:
        secret = _with_refs(Secret.objects).get(hashid=hashid)
    except Secret.DoesNotExist as exc:
        raise HttpError(404, f'No secret with hashid {hashid}') from exc

    try:
        secret.check_read_access(user)
    except Http404 as exc:
        raise HttpError(404, f'No secret with hashid {hashid}') from exc
    except PermissionDenied as exc:
        raise HttpError(403, 'You do not have read access to this secret') from exc

    return build_secret_schema(user, secret, expanded)


PAYLOAD_RESPONSE = PasswordPayload | CreditCardPayload | FilePayload

DATA_SIDE_EFFECTS = (
    "Reading the payload is audited: it records the calling user in the payload's `accessed_by`"
    ' set, updates `last_read`, and writes a secret-read entry to the audit log (a dedicated'
    ' elevated-read category when a superuser reads a secret they only see via superuser privileges).'
)


@router.get(
    '/{hashid}/data',
    response={200: PAYLOAD_RESPONSE, codes_4xx: ErrorDetail},
    operation_id='get_secret_data',
    summary="Read a secret's current payload",
    description=(
        'Decrypts and returns the current payload of a secret. The response shape depends on the'
        " secret's `content_type`: a password returns `{password, otp_key_data}`, a credit card"
        ' returns its card fields, and a file returns `{filename, file_content}` with the contents'
        " base64-encoded (v2 uses `file_content`, fixing v1's `file` key).\n\n"
        '- **Required scope**: `secrets:data:read` (never implied by `secrets:read`/`secrets:write`)\n'
        f'- **Side effects**: {DATA_SIDE_EFFECTS}\n'
        '- **Related**: `get_secret`, `get_secret_revision_data`'
    ),
)
@requires_scope('secrets:data:read')
def get_secret_data(request, hashid: str) -> PAYLOAD_RESPONSE:
    user = request.auth.user
    secret = readable_secret(user, hashid)
    data = secret.get_data(user)
    return serialize_payload(secret.content_type, data, secret.filename)


@router.get(
    '/{hashid}/revisions/{revision_hashid}/data',
    response={200: PAYLOAD_RESPONSE, codes_4xx: ErrorDetail},
    operation_id='get_secret_revision_data',
    summary="Read a specific revision's payload",
    description=(
        'Decrypts and returns the payload of a specific revision (a `SecretChange`) of a secret,'
        ' identified by `revision_hashid`. Returns 404 if the revision does not belong to the'
        ' given secret. The response shape matches `get_secret_data`.\n\n'
        '- **Required scope**: `secrets:data:read` (never implied by `secrets:read`/`secrets:write`)\n'
        f'- **Side effects**: {DATA_SIDE_EFFECTS}\n'
        '- **Related**: `get_secret_data`'
    ),
)
@requires_scope('secrets:data:read')
def get_secret_revision_data(request, hashid: str, revision_hashid: str) -> PAYLOAD_RESPONSE:
    user = request.auth.user
    secret = readable_secret(user, hashid)
    try:
        change = SecretChange.objects.select_related('revision').get(hashid=revision_hashid, secret=secret)
    except SecretChange.DoesNotExist as exc:
        raise HttpError(404, f'No revision with hashid {revision_hashid} for this secret') from exc
    data = change.revision.get_data(user)
    return serialize_payload(secret.content_type, data, change.filename)


@router.get(
    '/{hashid}/otp',
    response={200: OtpToken, codes_4xx: ErrorDetail},
    operation_id='get_secret_otp',
    summary="Read a secret's current OTP token",
    description=(
        'Computes and returns the current one-time password (TOTP) token for a password secret that'
        ' has an OTP key configured. Returns 422 if the secret has no OTP key.\n\n'
        '- **Required scope**: `secrets:data:read` (never implied by `secrets:read`/`secrets:write`)\n'
        f'- **Side effects**: {DATA_SIDE_EFFECTS} The decrypted OTP key is cached in your session,'
        ' so repeatedly refreshing the token within one session (cookie-retaining clients) does not'
        ' multiply audit log entries.\n'
        '- **Related**: `get_secret_data`'
    ),
)
@requires_scope('secrets:data:read')
def get_secret_otp(request, hashid: str) -> OtpToken:
    user = request.auth.user
    secret = readable_secret(user, hashid)
    if secret.content_type != ContentType.PASSWORD or not (
        secret.current_revision and secret.current_revision.otp_key_set
    ):
        raise HttpError(422, 'This secret has no OTP key configured')
    # get_otp() reads the acting user from request.user and caches the OTP key in request.session;
    # bind request.user to the token's user so the cached-read audit semantics match the web UI.
    request.user = user
    return OtpToken(otp=secret.get_otp(request))


@router.post(
    '/',
    response={201: SecretSchema, 422: ErrorDetail, codes_4xx: ErrorDetail},
    operation_id='create_secret',
    summary='Create a secret',
    description=(
        'Creates a secret with metadata and an initial payload (`secret_data`, write-only). The shape'
        ' of `secret_data` depends on `content_type` (same vocabulary as the payload-read endpoints,'
        ' with `file_content` base64-encoded). The creator is automatically granted a permanent share,'
        ' matching the legacy `/api/` behaviour. Returns the full secret.\n\n'
        '- **Required scope**: `secrets:write` (does not grant `secrets:data:read`)\n'
        '- **Validation**: 422 if `secret_data` does not match `content_type` (e.g. missing credit-card'
        ' fields, or a file without `filename`/`file_content`)\n'
        '- **Related**: `update_secret`, `get_secret`'
    ),
)
@requires_scope('secrets:write')
def create_secret(request, payload: SecretCreateRequest):
    user = request.auth.user
    content_type = _enum_or_422(payload.content_type, REPR_CONTENT_TYPE, 'content_type')
    access_policy = _enum_or_422(payload.access_policy, REPR_ACCESS_POLICY, 'access_policy')

    try:
        data, filename = normalize_payload(content_type, payload.secret_data)
    except PayloadValidationError as exc:
        return 422, ErrorDetail(detail=exc.errors)

    with transaction.atomic():
        secret = Secret.objects.create(
            name=payload.name,
            content_type=content_type,
            access_policy=access_policy,
            url=payload.url,
            username=payload.username,
            description=payload.description,
            needs_changing_on_leave=payload.needs_changing_on_leave,
            filename=filename,
            created_by=user,
        )
        secret.shared_users.add(user)
        RevisionService.save_payload(secret=secret, actor=user, payload=data, skip_acl=True)

    secret = _with_refs(Secret.objects).get(pk=secret.pk)
    return 201, build_secret_schema(user, secret)


@router.patch(
    '/{hashid}',
    response={200: SecretSchema, 422: ErrorDetail, codes_4xx: ErrorDetail},
    operation_id='update_secret',
    summary='Update a secret',
    description=(
        "Updates a secret's metadata and/or payload. Every field is optional; only provided fields"
        ' change. `content_type` is immutable: sending a different value is rejected with 422. When'
        ' `secret_data` is provided it is validated against the existing content type and saved as a'
        ' new payload revision (re-using an existing revision when the plaintext is unchanged).\n\n'
        '- **Required scope**: `secrets:write` (does not grant `secrets:data:read`)\n'
        '- **Permissions**: an invisible secret returns 404, a visible-but-unwritable secret returns 403'
        " (same gate as v1's update path)\n"
        '- **Related**: `create_secret`, `get_secret`'
    ),
)
@requires_scope('secrets:write')
def update_secret(request, hashid: str, payload: SecretUpdateRequest):
    user = request.auth.user
    secret = writable_secret(user, hashid)

    if payload.content_type is not None and CONTENT_TYPE_REPR[secret.content_type] != payload.content_type:
        raise HttpError(422, 'content_type is immutable and cannot be changed after creation')

    data = None
    if payload.secret_data is not None:
        try:
            data, filename = normalize_payload(secret.content_type, payload.secret_data)
        except PayloadValidationError as exc:
            return 422, ErrorDetail(detail=exc.errors)
        if filename is not None:
            secret.filename = filename

    with transaction.atomic():
        # access_policy is handled apart from the plain-field loop below because its wire value
        # needs the enum repr -> int mapping first.
        if payload.access_policy is not None:
            secret.access_policy = _enum_or_422(payload.access_policy, REPR_ACCESS_POLICY, 'access_policy')
        for field in ('name', 'url', 'username', 'description', 'needs_changing_on_leave'):
            value = getattr(payload, field)
            if value is not None:
                setattr(secret, field, value)
        secret.save()

        if data is not None:
            RevisionService.save_payload(secret=secret, actor=user, payload=data)

    secret = _with_refs(Secret.objects).get(pk=secret.pk)
    return build_secret_schema(user, secret)


@router.delete(
    '/{hashid}',
    response={204: None, codes_4xx: ErrorDetail},
    operation_id='delete_secret',
    summary='Delete a secret',
    description=(
        'Soft-deletes a secret: its `status` becomes `deleted` and it disappears from the default'
        ' list/visibility (the row is never hard-deleted, preserving history and audit trail).\n\n'
        '- **Required scope**: `secrets:write` (does not grant `secrets:data:read`)\n'
        '- **Permissions**: an invisible secret returns 404, a visible-but-unwritable secret returns 403\n'
        '- **Related**: `update_secret`'
    ),
)
@requires_scope('secrets:write')
def delete_secret(request, hashid: str):
    user = request.auth.user
    secret = writable_secret(user, hashid)
    secret.status = SecretStatus.DELETED
    secret.save(update_fields=['status'])
    return 204, None
