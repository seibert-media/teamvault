import datetime

from ninja import Router, Schema
from ninja.responses import codes_4xx
from pydantic import Field

from teamvault.api.v2.schemas import ErrorDetail, UserRef, user_ref
from teamvault.api.v2.scopes import public_endpoint

router = Router(tags=['me'])


class TokenInfo(Schema):
    """Metadata about the API token authenticating the current request."""

    name: str = Field(
        description='Human-readable label given when the token was issued.',
        examples=['CI deploy key'],
    )
    prefix: str = Field(
        description='Public token prefix (the part before the dot in the bearer token).',
        examples=['Yx3kP0aBcDeF'],
    )
    scopes: list[str] = Field(
        description='Scopes granted to this token.',
        examples=[['secrets:read', 'secrets:data:read']],
    )
    expires_at: datetime.date = Field(
        description='Date on which this token expires.',
        examples=['2026-12-31'],
    )


class MeResponse(Schema):
    """Identity of the calling token and its user."""

    user: UserRef = Field(
        description='The user this token belongs to.',
        examples=[{'id': 42, 'username': 'jdoe', 'full_name': 'John Doe'}],
    )
    token: TokenInfo = Field(
        description='The token used to authenticate this request.',
        examples=[
            {
                'name': 'CI deploy key',
                'prefix': 'Yx3kP0aBcDeF',
                'scopes': ['secrets:read', 'secrets:data:read'],
                'expires_at': '2026-12-31',
            }
        ],
    )


@router.get(
    '/me',
    response={200: MeResponse, codes_4xx: ErrorDetail},
    operation_id='get_me',
    summary='Identify the calling token',
    description=(
        'Self-introspection: returns the user behind the bearer token used for this request,'
        ' plus the token metadata (scopes, expiry). Useful for agents to discover which'
        ' operations their token permits.\n\n'
        '- **Required scope**: none — any valid token'
    ),
)
@public_endpoint
def get_me(request):
    token = request.auth
    return MeResponse(
        user=user_ref(token.user),
        token=TokenInfo(name=token.name, prefix=token.prefix, scopes=token.scopes, expires_at=token.expires_at),
    )
