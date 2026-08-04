import datetime

from ninja import Schema
from pydantic import Field


class ErrorDetail(Schema):
    """Error envelope used by every 4xx/5xx response."""

    detail: str | list = Field(
        description='Human-readable error message, or a list of field-level error objects for validation errors.',
        examples=['Missing required scope: secrets:read'],
    )


class UserRef(Schema):
    """Slim reference to a user; expandable to the full User schema where documented."""

    id: int = Field(
        description='Stable numeric identifier of the user.',
        examples=[42],
    )
    username: str = Field(
        description='Login name of the user.',
        examples=['jdoe'],
    )
    full_name: str = Field(
        description='Display name of the user (first and last name; may be empty).',
        examples=['John Doe'],
    )


class GroupRef(Schema):
    """Slim reference to a group; expandable to the full Group schema where documented."""

    id: int = Field(
        description='Stable numeric identifier of the group.',
        examples=[7],
    )
    name: str = Field(
        description='Name of the group.',
        examples=['ops'],
    )


class Group(Schema):
    """Full group resource; the expansion target for a GroupRef.

    TeamVault stores no group attributes beyond id and name, so the expanded Group has the same
    shape as a GroupRef. It exists as a distinct schema so `?expand=group` is documented and so the
    representation can grow without a breaking change if richer group data is added later.
    """

    id: int = Field(
        description='Stable numeric identifier of the group.',
        examples=[7],
    )
    name: str = Field(
        description='Name of the group.',
        examples=['ops'],
    )


class User(Schema):
    """Full user resource; the expansion target for a UserRef."""

    id: int = Field(
        description='Stable numeric identifier of the user.',
        examples=[42],
    )
    username: str = Field(
        description='Login name of the user.',
        examples=['jdoe'],
    )
    full_name: str = Field(
        description='Display name of the user (first and last name; may be empty).',
        examples=['John Doe'],
    )
    email: str = Field(
        description='Email address of the user (may be empty).',
        examples=['john.doe@example.com'],
    )
    is_active: bool = Field(
        description='Whether the user account is active.',
        examples=[True],
    )


class SecretRef(Schema):
    """Slim reference to a secret; addressed by its stable hashid."""

    hashid: str = Field(
        description='Stable identifier of the secret (the same identifier the legacy `/api/` used).',
        examples=['k3mZpqR7'],
    )
    name: str = Field(
        description='Human-readable name of the secret.',
        examples=['Production database password'],
    )


class PayloadRef(Schema):
    """Slim reference to a payload (an encrypted secret revision).

    A payload is the deduplicated encrypted blob behind a secret: saving the same plaintext
    twice reuses one payload row, so several revisions in a secret's history may share the
    same payload (and thus the same `hashid`). Decrypt the current payload via
    `GET /v2/secrets/{hashid}/data`, or a historical one via
    `GET /v2/secrets/{hashid}/revisions/{revision_hashid}/data`.
    """

    hashid: str = Field(
        description='Stable identifier of the payload (the secret revision holding the encrypted blob).',
        examples=['k3mZpqR7'],
    )
    created_at: datetime.datetime = Field(
        description='When this payload was first created (model field `created`).',
        examples=['2026-01-15T09:30:00Z'],
    )
    set_by: UserRef = Field(
        description='The user who set this payload (model field `set_by`).',
        examples=[{'id': 42, 'username': 'jdoe', 'full_name': 'John Doe'}],
    )


def group_ref(group) -> GroupRef:
    return GroupRef(id=group.pk, name=group.name)


def group_detail(group) -> Group:
    return Group(id=group.pk, name=group.name)


def user_ref(user) -> UserRef:
    return UserRef(id=user.pk, username=user.username, full_name=user.get_full_name())


def user_detail(user) -> User:
    return User(
        id=user.pk,
        username=user.username,
        full_name=user.get_full_name(),
        email=user.email or '',
        is_active=user.is_active,
    )
