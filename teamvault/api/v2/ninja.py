from ninja import NinjaAPI

from teamvault.api.v2.authentication import BearerAuth
from teamvault.api.v2.docs import ElementsDocs
from teamvault.api.v2.me import router as me_router
from teamvault.api.v2.secrets.revisions import router as revisions_router
from teamvault.api.v2.secrets.router import router as secrets_router
from teamvault.api.v2.secrets.shares import router as shares_router
from teamvault.api.v2.users.router import router as users_router
from teamvault.api.v2.utility import router as utility_router

API_DESCRIPTION = """
API for TeamVault, the shared password manager: secrets (passwords, credit cards, files),
their payloads, shares, and revision history.

## Authentication

Every endpoint requires a bearer token (exceptions: `GET /v2/me` and
`GET /v2/password-suggestion` require a token but no scope; this documentation is public):

```
Authorization: Bearer <prefix>.<secret>
```

Tokens are issued in your TeamVault user settings (or by an administrator via the
`issue_api_token` management command) and carry **scopes**; each operation documents its
required scope. Call `GET /v2/me` to see who you are and which scopes your token holds.
Wildcard scopes (`secrets:*`) match every action on that resource. Reading decrypted
payloads requires the dedicated `secrets:data:read` scope — it is never implied by
`secrets:read` or `secrets:write`. Scopes only narrow what the token's user may already
do; they never grant access beyond the user's own permissions.

## Errors

All 4xx/5xx responses use a single envelope:

```json
{"detail": "Missing required scope: secrets:read"}
```

For validation errors (422), `detail` is a list of field-level error objects.

## Conventions for list endpoints

- **Pagination**: `?page=&page_size=` — response envelope `{count, next, previous, results}`.
  Default `page_size` is 50, maximum 200 (silently clamped).
- **Filtering**: each list endpoint documents its filter parameters. Unknown query parameters
  are rejected with 422. Multiple filters combine with AND.
- **Sorting**: `?sort=key,-key2` — comma-separated, `-` prefix for descending,
  per-endpoint allowlist of sort keys.
- **Expand**: `?expand=a,b` — opt into full objects in place of slim references,
  per-endpoint allowlist, one level deep. Unknown values are rejected with 422.

## Identifiers

Secrets and revisions are addressed by their stable `hashid` (the same identifier the
legacy `/api/` used). Users and shares are addressed by their numeric `id`; users are
never addressed by username (usernames can change).

## Migrating from the legacy DRF API

The legacy `/api/` (v1) endpoints are deprecated but frozen and still supported; every v1 response
carries RFC 8594 `Deprecation` and `Link` headers. See the migration guide at
[`/api/v2/MIGRATION.md`](/api/v2/MIGRATION.md) for the endpoint and field mapping from the
deprecated `/api/` endpoints (auth, paths, and per-resource field renames).
"""

api = NinjaAPI(
    title='TeamVault API',
    version='2.0.0',
    description=API_DESCRIPTION,
    auth=BearerAuth(),
    urls_namespace='api-v2',
    docs=ElementsDocs(),
    docs_url='/docs',
    openapi_url='/openapi.json',
)

api.add_router('', me_router)
api.add_router('', utility_router)
api.add_router('/secrets', secrets_router)
api.add_router('/secrets', shares_router)
api.add_router('/secrets', revisions_router)
api.add_router('/users', users_router)
