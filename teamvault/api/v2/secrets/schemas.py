"""v2 Secret resource schema and the bulk builders that turn Secret rows into it.

Builders resolve all refs (created_by, current_payload, data_readable) with bulk queries
over a whole page, so neither the list nor the detail endpoint does per-row lookups.
"""

import datetime
from base64 import b64encode

from django.conf import settings
from django.utils.timezone import now
from ninja import Field, Schema

from teamvault.api.v2.schemas import (
    Group,
    GroupRef,
    PayloadRef,
    User,
    UserRef,
    group_detail,
    group_ref,
    user_detail,
    user_ref,
)
from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret, SecretChange, SharedSecretData

# Wire vocabulary: reuse v1's string mappings (teamvault/apps/secrets/api/serializers.py),
# except v1's content_type 'cc' is renamed to 'credit_card' in v2.
ACCESS_POLICY_REPR = {
    AccessPolicy.ANY: 'any',
    AccessPolicy.DISCOVERABLE: 'discoverable',
    AccessPolicy.HIDDEN: 'hidden',
}
REPR_ACCESS_POLICY = {value: key for key, value in ACCESS_POLICY_REPR.items()}

CONTENT_TYPE_REPR = {
    ContentType.PASSWORD: 'password',
    ContentType.CC: 'credit_card',
    ContentType.FILE: 'file',
}
REPR_CONTENT_TYPE = {value: key for key, value in CONTENT_TYPE_REPR.items()}

STATUS_REPR = {
    SecretStatus.OK: 'ok',
    SecretStatus.NEEDS_CHANGING: 'needs_changing',
    SecretStatus.DELETED: 'deleted',
}
REPR_STATUS = {value: key for key, value in STATUS_REPR.items()}


class SecretSchema(Schema):
    """A secret: its metadata and a reference to its current payload.

    The decrypted payload is never part of this resource; fetch it separately via the
    current payload's `/data` endpoint (requires the `secrets:data:read` scope).
    """

    hashid: str = Field(
        description='Stable identifier of the secret (the same id the legacy /api/ used).',
        examples=['8xKq2mLp'],
    )
    name: str = Field(description='Human-readable name of the secret.', examples=['Production database'])
    url: str | None = Field(description='Optional URL the secret applies to.', examples=['https://db.example.com'])
    username: str | None = Field(description='Optional username stored with the secret.', examples=['dbadmin'])
    description: str | None = Field(
        description='Optional free-text description.', examples=['Read-write credentials for the prod cluster.']
    )
    filename: str | None = Field(
        description='Original filename for file secrets; null for passwords and credit cards.',
        examples=['service-account.json'],
    )
    content_type: str = Field(
        description="Kind of secret. One of 'password', 'credit_card', 'file' "
        "(model field `content_type`; v1's 'cc' is renamed to 'credit_card').",
        examples=['password'],
    )
    access_policy: str = Field(
        description="Who may discover and read the secret. One of 'any', 'discoverable', 'hidden'.",
        examples=['discoverable'],
    )
    status: str = Field(
        description="Lifecycle status. One of 'ok', 'needs_changing', 'deleted'.",
        examples=['ok'],
    )
    needs_changing_on_leave: bool = Field(
        description='Whether this secret must be rotated when a person with access leaves.',
        examples=[True],
    )
    created_at: datetime.datetime = Field(
        description='When the secret was created (model field `created`).',
        examples=['2026-01-15T09:30:00Z'],
    )
    last_changed_at: datetime.datetime = Field(
        description='When the secret metadata was last changed (model field `last_changed`).',
        examples=['2026-02-01T11:00:00Z'],
    )
    last_read_at: datetime.datetime = Field(
        description='When the secret payload was last read (model field `last_read`).',
        examples=['2026-03-10T14:20:00Z'],
    )
    created_by: UserRef | User = Field(
        description='The user who created the secret. Slim reference by default; full User with ?expand=created_by.',
        examples=[{'id': 42, 'username': 'jdoe', 'full_name': 'John Doe'}],
    )
    current_payload: PayloadRef | None = Field(
        description="Reference to the secret's current payload (v1 `current_revision`), or null if it has none yet.",
        examples=[
            {
                'hashid': 'k3mZpqR7',
                'created_at': '2026-01-15T09:30:00Z',
                'set_by': {'id': 42, 'username': 'jdoe', 'full_name': 'John Doe'},
            }
        ],
    )
    data_readable: bool = Field(
        description="Whether the calling user may decrypt this secret's payload (their own permissions, "
        'independent of token scope).',
        examples=[True],
    )
    web_url: str = Field(
        description='Absolute URL of the secret in the TeamVault web UI.',
        examples=['https://teamvault.example.com/secrets/8xKq2mLp/'],
    )


def _readable_secret_pks(user, secrets: list[Secret]) -> set[int]:
    """Bulk-compute, for the given page of secrets, which the user may decrypt.

    Mirrors PermissionChecker.is_readable() but resolves every secret's shares in one query
    instead of one per row. Superusers (with ALLOW_SUPERUSER_READS) read everything.
    """
    if not secrets:
        return set()
    pks = [secret.pk for secret in secrets]
    if user.is_superuser and settings.ALLOW_SUPERUSER_READS:
        return set(pks)

    shares = SharedSecretData.objects.for_user(user).filter(secret__in=pks)
    # is_readable() grants ALLOWED on any non-expired share (for_user already excludes expired)
    # and TEMPORARILY_ALLOWED also counts as readable (non-zero AccessPermissionTypes).
    shared_pks = set(shares.values_list('secret_id', flat=True))
    any_policy_pks = {secret.pk for secret in secrets if secret.access_policy == AccessPolicy.ANY}
    # is_readable() returns NOT_ALLOWED for deleted secrets regardless of policy or shares.
    # Current callers never pass deleted secrets, but keep the bulk version self-defending.
    deleted_pks = {secret.pk for secret in secrets if secret.status == SecretStatus.DELETED}
    return (shared_pks | any_policy_pks) - deleted_pks


def build_secret_schemas(user, secrets: list[Secret], expanded: frozenset[str] | set[str]) -> list[SecretSchema]:
    """Build the v2 schema for a page of secrets with bulk ref resolution (no per-row queries).

    `secrets` should already have `created_by` and `current_revision` (+ its `set_by`)
    selected via select_related on the queryset.
    """
    readable = _readable_secret_pks(user, secrets)
    expand_created_by = 'created_by' in expanded

    def created_by_field(secret: Secret) -> UserRef | User:
        return user_detail(secret.created_by) if expand_created_by else user_ref(secret.created_by)

    def payload_field(secret: Secret) -> PayloadRef | None:
        revision = secret.current_revision
        if revision is None:
            return None
        return PayloadRef(hashid=revision.hashid, created_at=revision.created, set_by=user_ref(revision.set_by))

    return [
        SecretSchema(
            hashid=secret.hashid,
            name=secret.name,
            url=secret.url,
            username=secret.username,
            description=secret.description,
            filename=secret.filename,
            content_type=CONTENT_TYPE_REPR[secret.content_type],
            access_policy=ACCESS_POLICY_REPR[secret.access_policy],
            status=STATUS_REPR[secret.status],
            needs_changing_on_leave=secret.needs_changing_on_leave,
            created_at=secret.created,
            last_changed_at=secret.last_changed,
            last_read_at=secret.last_read,
            created_by=created_by_field(secret),
            current_payload=payload_field(secret),
            data_readable=secret.pk in readable,
            web_url=secret.full_url,
        )
        for secret in secrets
    ]


def build_secret_schema(user, secret: Secret, expanded: frozenset[str] | set[str] = frozenset()) -> SecretSchema:
    return build_secret_schemas(user, [secret], expanded)[0]


class PasswordPayload(Schema):
    """Decrypted payload of a password secret."""

    password: str = Field(description='The decrypted password.', examples=['s3cr3t-p@ssw0rd'])
    otp_key_data: str = Field(
        description='The stored otpauth OTP key data, or an empty string if the secret has no OTP configured.',
        examples=['otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=6'],
    )


class CreditCardPayload(Schema):
    """Decrypted payload of a credit card secret."""

    holder: str = Field(description='Name of the card holder.', examples=['Jane Doe'])
    expiration_month: str = Field(description='Two-digit expiration month.', examples=['12'])
    expiration_year: str = Field(description='Four-digit expiration year.', examples=['2030'])
    number: str = Field(description='The card number.', examples=['4111111111111111'])
    security_code: str = Field(description='The card security code (CVC/CVV).', examples=['123'])
    password: str = Field(description='Optional card PIN or password (may be empty).', examples=[''])


class FilePayload(Schema):
    """Decrypted payload of a file secret.

    Unlike v1 (which returned the bytes under a `file` key), v2 returns them under `file_content`.
    """

    filename: str = Field(description='Original filename of the stored file.', examples=['service-account.json'])
    file_content: str = Field(
        description='Base64-encoded file contents.',
        examples=['aGVsbG8tZnJvbS1ieXRlcw=='],
    )


class OtpToken(Schema):
    """A freshly computed one-time password (TOTP) token."""

    otp: str = Field(description='The current OTP token.', examples=['123456'])


class SecretCreateRequest(Schema):
    """Payload for creating a secret. The shape of `secret_data` depends on `content_type`."""

    model_config = {'extra': 'forbid'}

    name: str = Field(description='Human-readable name of the secret.', examples=['Production database'])
    content_type: str = Field(
        description="Kind of secret. One of 'password', 'credit_card', 'file'. Immutable after creation.",
        examples=['password'],
    )
    secret_data: dict = Field(
        description='The write-only payload. Shape depends on `content_type`: password -> {password, '
        'optional otp_key_data}; credit_card -> {holder, number, expiration_month, expiration_year, '
        'security_code, optional password}; file -> {filename, file_content (base64)}.',
        examples=[{'password': 's3cr3t-p@ssw0rd'}],
    )
    access_policy: str = Field(
        'discoverable',
        description="Who may discover and read the secret. One of 'any', 'discoverable', 'hidden'.",
        examples=['discoverable'],
    )
    url: str | None = Field(
        None, description='Optional URL the secret applies to.', examples=['https://db.example.com']
    )
    username: str | None = Field(None, description='Optional username stored with the secret.', examples=['dbadmin'])
    description: str | None = Field(
        None, description='Optional free-text description.', examples=['Read-write credentials for the prod cluster.']
    )
    needs_changing_on_leave: bool = Field(
        True,
        description='Whether this secret must be rotated when a person with access leaves.',
        examples=[True],
    )


class SecretUpdateRequest(Schema):
    """Payload for updating a secret. Every field is optional; only provided fields change.

    `content_type` is immutable: sending a value different from the secret's current content type
    is rejected with 422.
    """

    model_config = {'extra': 'forbid'}

    name: str | None = Field(None, description='Human-readable name of the secret.', examples=['Production database'])
    content_type: str | None = Field(
        None,
        description="Immutable. Sending a value different from the secret's content type is rejected (422).",
        examples=['password'],
    )
    secret_data: dict | None = Field(
        None,
        description="New write-only payload (same shape rules as create, matched to the secret's content type).",
        examples=[{'password': 's3cr3t-p@ssw0rd'}],
    )
    access_policy: str | None = Field(
        None,
        description="Who may discover and read the secret. One of 'any', 'discoverable', 'hidden'.",
        examples=['discoverable'],
    )
    url: str | None = Field(
        None, description='Optional URL the secret applies to.', examples=['https://db.example.com']
    )
    username: str | None = Field(None, description='Optional username stored with the secret.', examples=['dbadmin'])
    description: str | None = Field(
        None, description='Optional free-text description.', examples=['Read-write credentials for the prod cluster.']
    )
    needs_changing_on_leave: bool | None = Field(
        None,
        description='Whether this secret must be rotated when a person with access leaves.',
        examples=[True],
    )


REQUIRED_CC_FIELDS = ('holder', 'expiration_month', 'expiration_year', 'number', 'security_code')


class PayloadValidationError(Exception):
    """Raised when a write payload does not match its content type.

    Carries ninja-style field-level error details for a 422 response.
    """

    def __init__(self, errors: list[dict]):
        self.errors = errors
        super().__init__('Invalid secret_data')


def _payload_error(field: str, message: str) -> PayloadValidationError:
    return PayloadValidationError([{'type': 'value_error', 'loc': ['body', 'secret_data', field], 'msg': message}])


def normalize_payload(content_type: int, secret_data: dict) -> tuple[dict, str | None]:
    """Validate `secret_data` against `content_type` and return `(payload dict, filename)`.

    Mirrors v1's per-content-type write shapes. The filename is only resolved for files (so the
    caller can persist it on the secret); it is None for the other content types. Raises
    PayloadValidationError (-> 422 with field detail) on any shape mismatch.
    """
    if content_type == ContentType.PASSWORD:
        if 'password' not in secret_data:
            raise _payload_error('password', 'This field is required for password secrets.')
        return {'password': secret_data['password'], 'otp_key_data': secret_data.get('otp_key_data', '')}, None

    if content_type == ContentType.CC:
        missing = [field for field in REQUIRED_CC_FIELDS if field not in secret_data]
        if missing:
            raise PayloadValidationError([
                {'type': 'missing', 'loc': ['body', 'secret_data', field], 'msg': 'This field is required.'}
                for field in missing
            ])
        return {
            'holder': secret_data['holder'],
            'expiration_month': secret_data['expiration_month'],
            'expiration_year': secret_data['expiration_year'],
            'number': secret_data['number'],
            'security_code': secret_data['security_code'],
            'password': secret_data.get('password', ''),
        }, None

    # FILE
    if 'filename' not in secret_data or 'file_content' not in secret_data:
        raise PayloadValidationError([
            {'type': 'missing', 'loc': ['body', 'secret_data', field], 'msg': 'This field is required.'}
            for field in ('filename', 'file_content')
            if field not in secret_data
        ])
    # Mirror v1's stored shape (serialize_file) byte-for-byte so identical plaintext dedups
    # across versions: the SHA256 dedup key is dumps() of this dict. The wire `file_content`
    # is already a base64 string, matching v1's base64-encoded value.
    return {'filename': secret_data['filename'], 'file_content': secret_data['file_content']}, secret_data['filename']


def serialize_payload(
    content_type: int, data, filename: str | None
) -> PasswordPayload | CreditCardPayload | FilePayload:
    """Turn a decrypted payload (as returned by Secret/SecretRevision.get_data) into its v2 schema.

    Mirrors v1's per-content-type response shapes, except file payloads use `file_content`
    (base64) instead of v1's `file` key. `data` is whatever get_data returned for the content type:
    a dict for passwords/credit cards, raw bytes for files. `filename` is required for files.
    """
    if content_type == ContentType.PASSWORD:
        # get_data returns a dict for structured payloads, or a bare string for legacy ones.
        if not isinstance(data, dict):
            return PasswordPayload(password=str(data), otp_key_data='')
        return PasswordPayload(password=data['password'], otp_key_data=data.get('otp_key_data', ''))
    if content_type == ContentType.CC:
        # Unlike legacy password payloads, CC payloads only exist as validated dicts with all
        # fields present (enforced by the write path), so no defensive handling here.
        return CreditCardPayload(
            holder=data['holder'],
            expiration_month=data['expiration_month'],
            expiration_year=data['expiration_year'],
            number=data['number'],
            security_code=data['security_code'],
            password=data['password'],
        )
    # FILE: get_data returns the raw decoded bytes; the filename comes from the secret/revision metadata.
    return FilePayload(filename=filename or '', file_content=b64encode(data).decode('ascii'))


class ShareSchema(Schema):
    """A grant of access to a secret, given to exactly one user or one group.

    Exactly one of `user`/`group` is set; the other is null. Slim references by default;
    expand `user`, `group`, and/or `granted_by` to full objects with `?expand=`.
    """

    id: int = Field(
        description='Stable numeric identifier of the share.',
        examples=[123],
    )
    user: UserRef | User | None = Field(
        description='The user this share grants access to, or null for a group share. Slim reference by '
        'default; full User with ?expand=user.',
        examples=[{'id': 42, 'username': 'jdoe', 'full_name': 'John Doe'}],
    )
    group: GroupRef | Group | None = Field(
        description='The group this share grants access to, or null for a user share. Slim reference by '
        'default; expand=group returns the same {id, name} shape (TeamVault stores no further group data).',
        examples=[{'id': 7, 'name': 'ops'}],
    )
    granted_by: UserRef | User | None = Field(
        description='The user who created this share, or null for system-created shares (e.g. the secret '
        "creator's automatic self-share). Slim reference by default; full User with ?expand=granted_by.",
        examples=[{'id': 42, 'username': 'jdoe', 'full_name': 'John Doe'}],
    )
    grant_description: str | None = Field(
        description='Free-text reason recorded when the share was created (may be null).',
        examples=['On-call access for incident #4711'],
    )
    granted_at: datetime.datetime | None = Field(
        description='When the share was created (model field `granted_on`; renamed to `granted_at` in v2).',
        examples=['2026-01-15T09:30:00Z'],
    )
    expires_at: datetime.datetime | None = Field(
        description='When the share expires, or null for a permanent share (model field `granted_until`; '
        'renamed to `expires_at` in v2).',
        examples=['2026-02-15T09:30:00Z'],
    )
    is_expired: bool = Field(
        description='Whether the share has expired (its `expires_at` is in the past).',
        examples=[False],
    )


class ShareCreateRequest(Schema):
    """Payload for sharing a secret with exactly one user or one group.

    Set exactly one of `user`/`group` (both or neither is rejected with 422). `expires_at` is
    optional; omit it (or send null) for a permanent share.
    """

    model_config = {'extra': 'forbid'}

    user: int | None = Field(
        None,
        description='Numeric id of the user to share with. Set this or `group`, never both.',
        examples=[42],
    )
    group: int | None = Field(
        None,
        description='Numeric id of the group to share with. Set this or `user`, never both.',
        examples=[7],
    )
    grant_description: str = Field(
        description='Free-text reason for granting access; recorded on the share and in the audit log.',
        examples=['On-call access for incident #4711'],
    )
    expires_at: datetime.datetime | None = Field(
        None,
        description='Optional expiry timestamp (model field `granted_until`; renamed to `expires_at` in v2). '
        'Omit or null for a permanent share.',
        examples=['2026-02-15T09:30:00Z'],
    )


def _is_expired(share: SharedSecretData) -> bool:
    # Mirror SecretShareQuerySet.with_expiry_state(): granted_until <= now is expired.
    return share.granted_until is not None and share.granted_until <= now()


class RevisionSchema(Schema):
    """One entry in a secret's history: a `SecretChange` row.

    A revision captures the secret's metadata snapshot at a point in time plus a reference to the
    payload (`SecretRevision`) that was current then. Payloads are deduplicated, so several
    revisions may share one `payload.hashid` (e.g. after a restore or a metadata-only edit). The
    decrypted payload content is never part of this resource; fetch it via
    `GET /v2/secrets/{hashid}/revisions/{revision_hashid}/data` (requires `secrets:data:read`).
    """

    hashid: str = Field(
        description='Stable identifier of the revision (the SecretChange hashid). Use it at the '
        '`/revisions/{revision_hashid}/data` endpoint to decrypt this revision.',
        examples=['c7Lm9Qr2'],
    )
    created_at: datetime.datetime = Field(
        description='When this revision was recorded (model field `created`).',
        examples=['2026-01-15T09:30:00Z'],
    )
    actor: UserRef | User = Field(
        description='The user who made this change. Slim reference by default; full User with ?expand=actor.',
        examples=[{'id': 42, 'username': 'jdoe', 'full_name': 'John Doe'}],
    )
    parent_hashid: str | None = Field(
        description='Hashid of the previous revision in the linear history chain (model field `parent`), '
        'or null for the first revision.',
        examples=['b3Kp8Wn1'],
    )
    restored_from_hashid: str | None = Field(
        description='If this revision was created by restoring an earlier one, the hashid of that source '
        'revision (model field `restored_from`); otherwise null.',
        examples=['a1Jq5Vm0'],
    )
    payload: PayloadRef = Field(
        description='Reference to the payload that was current at this revision (model field `revision`). '
        'Payloads are deduplicated, so several revisions may share one payload hashid.',
        examples=[
            {
                'hashid': 'k3mZpqR7',
                'created_at': '2026-01-15T09:30:00Z',
                'set_by': {'id': 42, 'username': 'jdoe', 'full_name': 'John Doe'},
            }
        ],
    )
    name: str = Field(description='Secret name at this revision.', examples=['Production database'])
    description: str | None = Field(
        description='Secret description at this revision.', examples=['Read-write credentials for the prod cluster.']
    )
    username: str | None = Field(description='Secret username at this revision.', examples=['dbadmin'])
    url: str | None = Field(description='Secret URL at this revision.', examples=['https://db.example.com'])
    filename: str | None = Field(
        description='Secret filename at this revision (file secrets only).', examples=['service-account.json']
    )
    access_policy: str = Field(
        description="Access policy at this revision. One of 'any', 'discoverable', 'hidden'.",
        examples=['discoverable'],
    )
    status: str = Field(
        description="Lifecycle status at this revision. One of 'ok', 'needs_changing', 'deleted'.",
        examples=['ok'],
    )
    needs_changing_on_leave: bool = Field(
        description='Whether the secret required rotation on leave at this revision.',
        examples=[True],
    )
    scrubbed_at: datetime.datetime | None = Field(
        description='When this revision had its metadata scrubbed by a superuser, or null if it was never '
        'scrubbed. When set, the snapshot fields above reflect the post-scrub state.',
        examples=['2026-04-01T08:00:00Z'],
    )
    scrubbed_by: UserRef | None = Field(
        description='The superuser who scrubbed this revision, or null if it was never scrubbed.',
        examples=[{'id': 1, 'username': 'admin', 'full_name': 'Site Admin'}],
    )


def build_revision_schemas(changes: list[SecretChange], expanded: frozenset[str] | set[str]) -> list[RevisionSchema]:
    """Build the v2 schema for a page of revisions with bulk ref resolution (no per-row queries).

    `changes` should already have `actor`, `scrubbed_by`, `revision`, `revision__set_by`, `parent`,
    and `restored_from` selected via select_related.
    """
    expand_actor = 'actor' in expanded

    def actor_field(change: SecretChange) -> UserRef | User:
        return user_detail(change.actor) if expand_actor else user_ref(change.actor)

    def scrubbed_by_field(change: SecretChange) -> UserRef | None:
        return user_ref(change.scrubbed_by) if change.scrubbed_by is not None else None

    def payload_field(change: SecretChange) -> PayloadRef:
        revision = change.revision
        return PayloadRef(hashid=revision.hashid, created_at=revision.created, set_by=user_ref(revision.set_by))

    return [
        RevisionSchema(
            hashid=change.hashid,
            created_at=change.created,
            actor=actor_field(change),
            parent_hashid=change.parent.hashid if change.parent_id else None,
            restored_from_hashid=change.restored_from.hashid if change.restored_from_id else None,
            payload=payload_field(change),
            name=change.name,
            description=change.description,
            username=change.username,
            url=change.url,
            filename=change.filename,
            access_policy=ACCESS_POLICY_REPR[change.access_policy],
            status=STATUS_REPR[change.status],
            needs_changing_on_leave=change.needs_changing_on_leave,
            scrubbed_at=change.scrubbed_at,
            scrubbed_by=scrubbed_by_field(change),
        )
        for change in changes
    ]


def build_share_schemas(shares: list[SharedSecretData], expanded: frozenset[str] | set[str]) -> list[ShareSchema]:
    """Build the v2 schema for a page of shares with bulk ref resolution (no per-row queries).

    `shares` should already have `user`, `group`, and `granted_by` selected via select_related.
    """
    expand_user = 'user' in expanded
    expand_group = 'group' in expanded
    expand_granted_by = 'granted_by' in expanded

    def user_field(share: SharedSecretData) -> UserRef | User | None:
        if share.user is None:
            return None
        return user_detail(share.user) if expand_user else user_ref(share.user)

    def group_field(share: SharedSecretData) -> GroupRef | Group | None:
        if share.group is None:
            return None
        return group_detail(share.group) if expand_group else group_ref(share.group)

    def granted_by_field(share: SharedSecretData) -> UserRef | User | None:
        if share.granted_by is None:
            return None
        return user_detail(share.granted_by) if expand_granted_by else user_ref(share.granted_by)

    return [
        ShareSchema(
            id=share.pk,
            user=user_field(share),
            group=group_field(share),
            granted_by=granted_by_field(share),
            grant_description=share.grant_description,
            granted_at=share.granted_on,
            expires_at=share.granted_until,
            is_expired=_is_expired(share),
        )
        for share in shares
    ]
