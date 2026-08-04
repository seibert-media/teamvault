"""Top-level utility endpoints that touch no stored data (like `/me`)."""

from django.conf import settings
from ninja import Router, Schema
from ninja.responses import codes_4xx
from pydantic import Field

from teamvault.api.v2.schemas import ErrorDetail
from teamvault.api.v2.scopes import public_endpoint
from teamvault.apps.secrets.utils import generate_password

router = Router(tags=['utility'])


class PasswordSuggestion(Schema):
    """A freshly generated password suggestion."""

    password: str = Field(
        description='A password generated from the configured password-generator settings.',
        examples=['xQ7!fP2$mLr9'],
    )


@router.get(
    '/password-suggestion',
    response={200: PasswordSuggestion, codes_4xx: ErrorDetail},
    operation_id='get_password_suggestion',
    summary='Generate a password suggestion',
    description=(
        'Returns a freshly generated password built from the configured password-generator settings'
        ' (length and minimum digits/upper/lower/special characters from the `[password_generator]`'
        " config section). The v2 home of v1's `/api/generate_password/`, now returning a `{password}`"
        ' object instead of a bare string.\n\n'
        '- **Required scope**: none — any valid token. Like `/me`, this endpoint touches no stored data'
        ' (it generates a random string), so it carries no scope; the bearer token is still required.'
    ),
)
@public_endpoint
def get_password_suggestion(request):  # noqa: ARG001 - ninja requires the first param to be named `request`
    password = generate_password(
        settings.PASSWORD_LENGTH,
        settings.PASSWORD_DIGITS,
        settings.PASSWORD_UPPER,
        settings.PASSWORD_LOWER,
        settings.PASSWORD_SPECIAL,
    )
    return PasswordSuggestion(password=password)
