# Migrating from the legacy `/api/` (v1) to `/api/v2/`

The v2 API is the supported surface for new integrations. The legacy DRF API under `/api/` is
**deprecated but frozen and safe**: it keeps working unchanged, and every v1 response now carries
RFC 8594 deprecation headers:

```
Deprecation: true
Link: </api/v2/MIGRATION.md>; rel="deprecation"
```

This document maps every v1 endpoint and every v1 field to its v2 equivalent so you can move at
your own pace. No deprecation timeline is announced — v1 stays available; this guide simply points
you at the better surface.

The full, always-current v2 contract (request/response schemas, examples) lives in the interactive
docs at `/api/v2/docs` and the machine-readable schema at `/api/v2/openapi.json`.

---

## 1. Authentication

| | v1 (legacy) | v2 |
|---|---|---|
| Scheme | HTTP Basic with your **user credentials** (username + password) | **Bearer token** |
| Header | `Authorization: Basic <base64(user:pass)>` | `Authorization: Bearer <prefix>.<secret>` |
| Scope | Full reach of your user account on every call | Token carries **scopes** that narrow what it may do |

### Getting a token

Issue a token in one of two ways:

- **Settings UI**: in your TeamVault user settings, create an API token, choose its scopes and
  expiry, and copy the `<prefix>.<secret>` value shown once.
- **Management command** (administrators): `issue_api_token` creates a token for a user from the
  command line (useful for service accounts / CI).

A token's scopes only ever **narrow** what its user may already do; they never grant access beyond
the user's own permissions. Call `GET /api/v2/me` to see who a token belongs to and which scopes it
holds.

### Choosing scopes

Pick the least-privileged set the integration needs:

| Scope | Grants | Notes |
|---|---|---|
| `secrets:read` | List/read secret **metadata**, revisions, and shares | Does **not** decrypt payloads |
| `secrets:data:read` | Decrypt payloads (`/data`, `/otp`) | Never implied by `secrets:read` or `secrets:write` |
| `secrets:write` | Create / update / delete secrets | Does **not** grant `secrets:data:read` or `shares:write` |
| `shares:write` | Create / delete shares | Never implied by `secrets:write` |
| `users:read` | List a user's pending secrets (offboarding) | Endpoint additionally requires a superuser token |
| _(none)_ | `GET /me`, `GET /password-suggestion` | Any valid token; these touch no stored data |

Wildcards (`secrets:*`, `shares:*`, `users:*`) match every action on that resource.

---

## 2. Endpoint mapping

Both APIs address **secrets** and **revisions** by the same stable `hashid`. The big structural
changes in v2:

- Payload reads are **secret-anchored**: instead of `secret-revisions/<hashid>/data`, you read the
  current payload at `secrets/<hashid>/data` (and a historical one at
  `secrets/<hashid>/revisions/<revision_hashid>/data`).
- Hyperlinked URLs are gone. v1 returned `api_url`, `current_revision`, and `data_url` as full
  URLs you had to follow. v2 returns plain `hashid`s (and a `current_payload` reference) that you
  compose into the paths below.
- Users and shares are addressed by **numeric `id`**, not by username/pk-in-URL.
- List endpoints gain pagination, filtering, sorting, and `expand` (see the API description at
  `/api/v2/docs`).

| v1 method + path | v2 method + path | Scope | Notes |
|---|---|---|---|
| `GET /api/secrets/` | `GET /api/v2/secrets/` | `secrets:read` | v1 `?search=` → v2 `?q=`; v2 adds paginated envelope, filters, sort, expand |
| `POST /api/secrets/` | `POST /api/v2/secrets/` | `secrets:write` | Creator still auto-shared. Returns 201 with the secret |
| `GET /api/secrets/<hashid>/` | `GET /api/v2/secrets/<hashid>` | `secrets:read` | |
| `PUT`/`PATCH /api/secrets/<hashid>/` | `PATCH /api/v2/secrets/<hashid>` | `secrets:write` | v2 is patch-only; only provided fields change; `content_type` immutable (422) |
| `DELETE /api/secrets/<hashid>/` | `DELETE /api/v2/secrets/<hashid>` | `secrets:write` | Soft delete (status → `deleted`); returns 204 |
| `GET /api/secrets/<hashid>/shares/` | `GET /api/v2/secrets/<hashid>/shares` | `secrets:read` | Paginated; filters `user`/`group`/`is_expired` |
| `POST /api/secrets/<hashid>/shares/` | `POST /api/v2/secrets/<hashid>/shares` | `shares:write` | `user`/`group` are now numeric **ids**, not username/name |
| `GET /api/secrets/<hashid>/shares/<pk>` | _(dropped)_ | — | No v2 share-detail GET; use `GET /api/v2/secrets/<hashid>/shares` and filter by `user`/`group` |
| `DELETE /api/secrets/<hashid>/shares/<pk>` | `DELETE /api/v2/secrets/<hashid>/shares/<id>` | `shares:write` | Returns 204 |
| `GET /api/secret-revisions/<hashid>/` | `GET /api/v2/secrets/<hashid>/revisions/<revision_hashid>` | `secrets:read` | Now anchored under its secret; also `GET …/revisions` lists history |
| `GET /api/secret-revisions/<hashid>/data` | `GET /api/v2/secrets/<hashid>/data` (current) or `GET /api/v2/secrets/<hashid>/revisions/<revision_hashid>/data` (historical) | `secrets:data:read` | The `<hashid>` that v1 used was the **revision** hashid; in v2 you address by the **secret** hashid (+ revision hashid for history) |
| `GET /api/secret-revisions/<hashid>/data/otp` | `GET /api/v2/secrets/<hashid>/otp` | `secrets:data:read` | 422 if the secret has no OTP key configured |
| `GET /api/generate_password/` | `GET /api/v2/password-suggestion` | _(none)_ | Returns `{"password": "..."}` instead of a bare JSON string |
| `GET /api/users/<username>/pending-secrets/` | `GET /api/v2/users/<user_id>/pending-secrets` | `users:read` (+ superuser token) | Addressed by numeric **user id**, not username |

No v1 route is dropped without a v2 home. There is no v2 equivalent of the legacy interactive
`/api-auth/` login (it was for v1's session login and is irrelevant under bearer auth).

---

## 3. Field mapping

Renames and shape changes are spelled out below per resource. v2 wire vocabulary reuses v1's string
enums (`access_policy`: `any`/`discoverable`/`hidden`; `status`: `ok`/`needs_changing`/`deleted`)
**except** `content_type` `cc` → `credit_card`.

### 3.1 Secret

v1 serializer: `SecretSerializer` / `SecretDetailSerializer`. v2 schema: `SecretSchema`.

| v1 field | v2 field | Change |
|---|---|---|
| `hashid` (added in `to_representation`) | `hashid` | unchanged |
| `name` | `name` | unchanged |
| `url` | `url` | unchanged |
| `username` | `username` | unchanged |
| `description` | `description` | unchanged |
| _(filename only in payload)_ | `filename` | **new** top-level field (null for non-file secrets) |
| `content_type` | `content_type` | value `cc` → `credit_card` |
| `access_policy` | `access_policy` | unchanged vocabulary |
| `status` | `status` | unchanged vocabulary |
| `needs_changing_on_leave` | `needs_changing_on_leave` | unchanged |
| `created` | `created_at` | **renamed** |
| `last_read` | `last_read_at` | **renamed** |
| _(not exposed in v1)_ | `last_changed_at` | **new** (model field `last_changed`) |
| `created_by` (username string) | `created_by` (`UserRef` `{id, username, full_name}`; `?expand=created_by` → full `User`) | shape change: object, not bare username |
| `current_revision` (hyperlink URL) | `current_payload` (`PayloadRef` `{hashid, created_at, set_by}`, or null) | **renamed + reshaped**: reference object instead of URL |
| `data_readable` | `data_readable` | unchanged |
| `web_url` | `web_url` | unchanged |
| `api_url` (self hyperlink) | — | **dropped**: compose `secrets/<hashid>` yourself |
| `secret_data` (write-only) | `secret_data` (write-only, in create/update bodies) | unchanged role; file uses `file_content` (see 3.5) |

### 3.2 Revision (history)

v1 serializer: `SecretRevisionSerializer` (a `SecretRevision`). v2 schema: `RevisionSchema` (a
`SecretChange`). v2 promotes history to a first-class, listable resource with far more detail.

| v1 field | v2 field | Change |
|---|---|---|
| `api_url` (self hyperlink) | — | **dropped**: address via `secrets/<hashid>/revisions/<revision_hashid>` |
| `created` | `created_at` | **renamed** |
| `set_by` (username string) | `payload.set_by` (`UserRef`) | moved under the `payload` reference; object not username |
| `data_url` (full URL) | _(read payload via `…/revisions/<revision_hashid>/data`)_ | **dropped**: derive the path from the hashids |
| — | `hashid` | **new** (the SecretChange hashid) |
| — | `actor` (`UserRef`; `?expand=actor`) | **new**: who made the change |
| — | `parent_hashid` | **new**: previous revision in the chain |
| — | `restored_from_hashid` | **new** |
| — | `payload` (`PayloadRef` `{hashid, created_at, set_by}`) | **new**: replaces v1's `data_url`/`api_url` |
| — | `name`, `description`, `username`, `url`, `filename`, `access_policy`, `status`, `needs_changing_on_leave` | **new**: full metadata snapshot at that revision |
| — | `scrubbed_at`, `scrubbed_by` | **new** |

> The v1 `data` payload under `secret-revisions/<hashid>/data` keyed file bytes as `file`. See 3.5.

### 3.3 Share

v1 serializer: `SharedSecretDataSerializer`. v2 schema: `ShareSchema`.

| v1 field | v2 field | Change |
|---|---|---|
| `id` | `id` | unchanged |
| `grant_description` | `grant_description` | unchanged |
| `granted_on` | `granted_at` | **renamed** |
| `granted_until` | `expires_at` | **renamed** |
| `group` (group **name** string) | `group` (`GroupRef` `{id, name}` or null; `?expand=group`) | shape change: object keyed by id, not bare name |
| `user` (**username** string) | `user` (`UserRef` `{id, username, full_name}` or null; `?expand=user`) | shape change: object, not bare username |
| `granted_by` (username string) | `granted_by` (`UserRef` or null; `?expand=granted_by`) | shape change: object, not bare username |
| `secret` (secret hashid string) | — | **dropped** from the body (the secret is in the path) |
| — | `is_expired` | **new**: computed |

**Share write bodies**: v1 took `user` (username) / `group` (group name) and `granted_until`. v2
takes `user` / `group` as **numeric ids** and `expires_at` (rename of `granted_until`).

### 3.4 Pending secrets (offboarding)

v1 serializer: `PendingSecretSerializer`. v2 schema: `PendingSecret`.

| v1 field | v2 field | Change |
|---|---|---|
| `hashid` | `hashid` | unchanged |
| `name` | `name` | unchanged |
| `type` (`get_content_type_display`, e.g. "Credit Card") | — | **dropped**: use `content_type` on the secret resource instead |
| `status` (`get_status_display`, e.g. "Needs Changing") | `status` (wire enum, e.g. `needs_changing`) | value change: enum string, not display label |
| `web_url` | `web_url` | unchanged |
| `last_changed` (string `%Y-%m-%d %H:%M:%S`) | `last_changed_at` (ISO 8601) | **renamed + ISO format** |
| `last_read` (string `%Y-%m-%d %H:%M:%S`) | `last_read_at` (ISO 8601) | **renamed + ISO format** |
| `last_shared` (string `%Y-%m-%d %H:%M:%S`) | `last_shared` (ISO 8601, nullable) | format change: ISO 8601 |

### 3.5 Decrypted payload (`/data`)

v1: `GET /api/secret-revisions/<hashid>/data`. v2: `GET /api/v2/secrets/<hashid>/data` (current) or
`…/revisions/<revision_hashid>/data` (historical). Both require `secrets:data:read` in v2.

| Content type | v1 response | v2 response | Change |
|---|---|---|---|
| password | `{"password": "..."}` | `{"password": "...", "otp_key_data": "..."}` | v2 also returns `otp_key_data` (empty string if none) |
| credit card (`cc`/`credit_card`) | `{holder, expiration_month, expiration_year, number, security_code, password}` | same fields | unchanged shape |
| file | `{"file": "<base64>"}` | `{"filename": "...", "file_content": "<base64>"}` | **`file` → `file_content`**, and `filename` is included |

**OTP**: v1 `…/data/otp` and v2 `secrets/<hashid>/otp` both return the current token. In v1 the
shape came straight from `get_otp`; v2 wraps it as `{"otp": "123456"}`.

### 3.6 Password suggestion

| v1 | v2 |
|---|---|
| `GET /api/generate_password/` → bare JSON string `"xQ7!fP2$mLr9"` | `GET /api/v2/password-suggestion` → `{"password": "xQ7!fP2$mLr9"}` |

---

## 4. Other v2 conventions

See the full description at `/api/v2/docs`. In brief:

- **Errors**: every 4xx/5xx uses one envelope `{"detail": ...}` (`detail` is a list of field-level
  objects for 422 validation errors).
- **Pagination**: `?page=&page_size=` → `{count, next, previous, results}` (default 50, max 200).
- **Filtering**: per-endpoint params, combined with AND; unknown query params are rejected (422).
- **Sorting**: `?sort=key,-key2`, per-endpoint allowlist.
- **Expand**: `?expand=a,b` to inline full objects in place of slim references, one level deep.
- **Identifiers**: secrets and revisions by `hashid`; users and shares by numeric `id`.
