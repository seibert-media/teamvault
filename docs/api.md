# TeamVault REST API

This documents the API as shipped in TeamVault 0.14.0. Every request and response below was
captured from a running instance, not transcribed from the source.

- [Basics](#basics)
- [Authentication](#authentication)
- [Pagination](#pagination)
- [The Secret resource](#the-secret-resource)
- [Payloads](#payloads)
- [Endpoints](#endpoints)
- [Errors](#errors)
- [Gotchas](#gotchas)

## Basics

The API is mounted at `/api/` relative to your installation, so on an instance reachable at
`https://teamvault.example.com` the secret list is `https://teamvault.example.com/api/secrets/`.

Requests and responses are JSON. Send `Content-Type: application/json` on writes.

Secrets and revisions are addressed by **hashid**, a short opaque string such as `5pG1xzxb`.
Integer primary keys are never exposed. Shares are the exception: they are addressed by their
integer `id`.

There is no version prefix and no OpenAPI schema in this release.

## Authentication

Every endpoint requires an authenticated user. The API accepts **HTTP Basic** with a TeamVault
username and password, and the session cookie a browser gets from logging in. There are no API
tokens.

```bash
curl -u alice:hunter2 https://teamvault.example.com/api/secrets/
```

Requests without usable credentials are rejected with **403**, not 401 — TeamVault's session
authenticator is consulted first and it does not emit a `WWW-Authenticate` challenge. Expect the
same status for a wrong password and for a malformed header:

```json
{"detail": "Authentication credentials were not provided."}
{"detail": "Invalid username/password."}
{"detail": "Invalid basic header. Credentials not correctly base64 encoded."}
```

Beyond authentication, every read is filtered by the caller's own permissions on each secret. A
superuser sees everything only if `allow_superuser_reads` is enabled in the config.

## Pagination

List endpoints return a fixed envelope:

```json
{
  "count": 3,
  "next": null,
  "previous": null,
  "results": []
}
```

Page size is **25** and is set server-side. `?page_size=` is ignored; the only pagination control
is `?page=<n>`. Asking for a page past the end returns **404** `{"detail": "Invalid page."}`, and so
does a non-numeric page.

Results are not explicitly ordered, so items can shift between pages as data changes. Do not rely
on a stable order across requests.

## The Secret resource

A secret is the metadata entity. Its confidential contents live in a separate revision (see
[Payloads](#payloads)).

```json
{
  "access_policy": "any",
  "api_url": "https://teamvault.example.com/api/secrets/5pG1xzxb/",
  "content_type": "password",
  "created": "2026-09-14T09:12:57.007565Z",
  "created_by": "alice",
  "current_revision": "https://teamvault.example.com/api/secret-revisions/e4n9DrwL/",
  "data_readable": 1,
  "description": null,
  "filename": null,
  "hashid": "5pG1xzxb",
  "last_read": "2026-09-14T09:12:57.022829Z",
  "name": "Example Password",
  "needs_changing_on_leave": true,
  "status": "ok",
  "url": null,
  "username": null,
  "web_url": "https://teamvault.example.com/secrets/5pG1xzxb/"
}
```

| Field | Type | Writable | Notes |
|---|---|---|---|
| `hashid` | string | no | Public identifier used in every URL. |
| `name` | string | yes | Required on create. |
| `content_type` | enum | on create only | `password`, `cc`, `file`. Fixed for the lifetime of the secret. |
| `access_policy` | enum | yes | `any`, `discoverable`, `hidden`. Defaults to `discoverable`. |
| `status` | enum | no in practice | `ok`, `needs_changing`, `deleted`. See [Gotchas](#gotchas). |
| `username` | string / null | yes | The login name the secret belongs to, free text. |
| `url` | string / null | yes | Must contain `://`. `javascript:` and `data:` are rejected. |
| `description` | string / null | yes | |
| `filename` | string / null | yes | Required for `file` secrets, rejected for all others. |
| `needs_changing_on_leave` | bool | yes | Flags the secret for offboarding. Defaults to `true`. |
| `created` | timestamp | no | |
| `created_by` | string | no | Username, not a URL or id. |
| `last_read` | timestamp | no | Updated whenever the payload is decrypted. |
| `current_revision` | URL / null | no | Points at the revision holding the current payload. |
| `data_readable` | integer | no | See below. |
| `api_url` | URL | no | Built from the request host. |
| `web_url` | URL | no | Built from the `base_url` config setting, not the request host. |

`data_readable` is an **integer**, despite the name reading like a boolean:

| Value | Meaning |
|---|---|
| `0` | Caller may not read the payload |
| `1` | Allowed through a normal share |
| `2` | Allowed through a share with an expiry date |
| `3` | Allowed because the caller is a superuser and `allow_superuser_reads` is on |

Treat any non-zero value as readable.

### Enum spellings

The API spells the enums differently from the database. Send and expect the API spellings:

- `content_type`: `password`, `cc`, `file` — note `cc`, not `credit_card`
- `access_policy`: `any`, `discoverable`, `hidden`
- `status`: `ok`, `needs_changing`, `deleted`

## Payloads

Confidential data is written through the `secret_data` object on a secret, and read back from a
revision's `/data` endpoint. `secret_data` is write-only: it never appears in a response.

Each write that changes the payload creates a new revision. Writing a payload identical to the
current one reuses the existing revision instead of creating a duplicate.

### Writing

**password**

```json
{"secret_data": {"password": "correct horse battery staple",
                 "otp_key_data": "otpauth://totp/ACME:john?secret=JBSWY3DPEHPK3PXP&digits=6&algorithm=SHA1"}}
```

`otp_key_data` is optional and is a full `otpauth://` URI, which TeamVault parses into the stored
key, digit count and algorithm. A URI without a `secret=` parameter stores no OTP at all.

**cc**

```json
{"secret_data": {"holder": "Jane Doe",
                 "number": "4111111111111111",
                 "expiration_month": "12",
                 "expiration_year": "2030",
                 "security_code": "123",
                 "password": "card-pin"}}
```

All six fields are required on every write, including `password` (send `""` if the card has no
PIN). There is no partial update for credit cards.

**file**

```json
{"secret_data": {"file_content": "ZmlsZSBieXRlcyBoZXJl"}}
```

`file_content` is base64. Whitespace and line breaks are stripped, but any other non-base64
character is rejected rather than silently dropped. The file's name is `filename` on the secret
itself, not part of the payload.

### Reading

`GET /api/secret-revisions/<hashid>/data` returns a different shape per content type:

| Content type | Response |
|---|---|
| `password` | `{"password": "correct horse battery staple"}` |
| `cc` | `{"holder": "...", "number": "...", "expiration_month": "...", "expiration_year": "...", "security_code": "...", "password": "..."}` |
| `file` | `{"file": "ZmlsZSBieXRlcyBoZXJl"}` |

Note the asymmetry on files: you write `file_content` and read back `file`. Both are base64.

A password payload's OTP key is never returned by `/data`. Fetch a current code from
`/data/otp` instead.

Every successful read is written to the audit log and bumps the secret's `last_read`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/secrets/` | List or search secrets |
| `POST` | `/api/secrets/` | Create a secret |
| `GET` | `/api/secrets/<hashid>/` | Read one secret |
| `PATCH` / `PUT` | `/api/secrets/<hashid>/` | Update metadata and/or payload |
| `DELETE` | `/api/secrets/<hashid>/` | Soft-delete a secret |
| `GET` | `/api/secrets/<hashid>/shares/` | List shares |
| `POST` | `/api/secrets/<hashid>/shares/` | Share with a user or group |
| `GET` | `/api/secrets/<hashid>/shares/<id>` | Read one share |
| `DELETE` | `/api/secrets/<hashid>/shares/<id>` | Revoke a share |
| `GET` | `/api/secret-revisions/<hashid>/` | Read revision metadata |
| `GET` | `/api/secret-revisions/<hashid>/data` | Decrypt the payload |
| `GET` | `/api/secret-revisions/<hashid>/data/otp` | Current OTP code |
| `GET` | `/api/generate_password/` | Suggest a password |
| `GET` | `/api/users/<username>/pending-secrets/` | Offboarding list (admin only) |

The share detail path has **no trailing slash**, unlike every other path here.

### List secrets

```bash
curl -u alice:hunter2 'https://teamvault.example.com/api/secrets/'
curl -u alice:hunter2 'https://teamvault.example.com/api/secrets/?search=production'
```

Without `search`, you get every secret *visible* to you, which includes `discoverable` secrets whose
payload you cannot read. With `search`, the same visibility rules apply and the term is matched
against the secret's searchable fields. `search` is the only supported filter; there is no sort
parameter.

### Create a secret

```bash
curl -u alice:hunter2 -X POST https://teamvault.example.com/api/secrets/ \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "Production DB",
        "content_type": "password",
        "access_policy": "discoverable",
        "username": "svc-account",
        "url": "https://example.com/login",
        "description": "created through the API",
        "secret_data": {"password": "correct horse battery staple"}
      }'
```

`name`, `content_type` and `secret_data` are required; `file` secrets additionally require
`filename`. Returns **201** with the full secret. The creator is granted access automatically.

### Update a secret

```bash
curl -u alice:hunter2 -X PATCH https://teamvault.example.com/api/secrets/5pG1xzxb/ \
  -H 'Content-Type: application/json' \
  -d '{"description": "now managed by the platform team"}'
```

Only `name`, `description`, `username`, `url`, `filename` and `access_policy` are applied. Anything
else in the body is ignored, including `content_type` and `status`. `PUT` and `PATCH` behave
identically, so a `PUT` with an empty body is a successful no-op rather than a reset.

Send `secret_data` to store a new payload:

```bash
curl -u alice:hunter2 -X PATCH https://teamvault.example.com/api/secrets/5pG1xzxb/ \
  -H 'Content-Type: application/json' \
  -d '{"secret_data": {"otp_key_data": "otpauth://totp/ACME:john?secret=JBSWY3DPEHPK3PXP&digits=6"}}'
```

For a password secret that already has a revision, `secret_data` is merged, so you can add or
replace the OTP key without resending the password. Credit card and file payloads are always
replaced whole.

### Delete a secret

```bash
curl -u alice:hunter2 -X DELETE https://teamvault.example.com/api/secrets/5pG1xzxb/
```

Returns **204**. This is a soft delete: `status` becomes `deleted` and the secret disappears from
lists and from `GET` by hashid (**404**), but the row and its revisions are retained.

### Shares

```bash
curl -u alice:hunter2 https://teamvault.example.com/api/secrets/5pG1xzxb/shares/
```

```json
{
  "grant_description": "on-call rotation",
  "granted_by": "alice",
  "granted_on": "2026-09-14T09:13:06.475762Z",
  "granted_until": "2027-01-01T00:00:00Z",
  "group": null,
  "id": 7,
  "secret": "5pG1xzxb",
  "user": "bob"
}
```

Users and groups are referenced by name, not id. Creating a share requires all four writable keys
in the body — `user`, `group`, `grant_description` and `granted_until` — with exactly one of `user`
and `group` set to a name and the other set to `null`:

```bash
curl -u alice:hunter2 -X POST https://teamvault.example.com/api/secrets/5pG1xzxb/shares/ \
  -H 'Content-Type: application/json' \
  -d '{"user": "bob", "group": null,
       "grant_description": "on-call rotation",
       "granted_until": "2027-01-01T00:00:00Z"}'
```

Use `"granted_until": null` for a share that does not expire. Omitting the `user` or `group` key
entirely causes a **500**; see [Gotchas](#gotchas). Sharing with someone who already has an
unexpired share returns **400**; an expired share may be replaced.

Revoking is `DELETE /api/secrets/<hashid>/shares/<id>` (no trailing slash), returning **204** and
writing an audit log entry.

### Revisions

```bash
curl -u alice:hunter2 https://teamvault.example.com/api/secret-revisions/e4n9DrwL/
```

```json
{
  "api_url": "https://teamvault.example.com/api/secret-revisions/e4n9DrwL/",
  "created": "2026-09-14T09:13:01.890893Z",
  "data_url": "https://teamvault.example.com/api/secret-revisions/e4n9DrwL/data",
  "set_by": "alice"
}
```

Revisions are read-only; `DELETE` returns **405**. There is no endpoint that lists a secret's
revision history — you can only reach the one under `current_revision`.

### OTP codes

```bash
curl -u alice:hunter2 https://teamvault.example.com/api/secret-revisions/e4n9DrwL/data/otp
```

Returns a bare JSON string, not an object:

```json
"372958"
```

The code is a TOTP generated from the stored key at request time, using the digit count and
algorithm captured from the `otpauth://` URI (defaulting to 6 digits and SHA1). Available only for
`password` secrets that actually carry an OTP key; anything else returns **400**
`["This secret has no OTP key."]`.

### Password suggestion

```bash
curl -u alice:hunter2 https://teamvault.example.com/api/generate_password/
```

Returns a bare JSON string such as `"b=K?](_zGvn62LP9"`, generated according to the
`[password_generator]` section of the server config. Takes no parameters.

### Pending secrets (offboarding)

```bash
curl -u admin:hunter2 'https://teamvault.example.com/api/users/bob/pending-secrets/?q=prod'
```

Lists the secrets to clean up after someone leaves. A secret appears here when all three hold: its
`status` is `needs_changing`, `needs_changing_on_leave` is true, and the named user actually
decrypted the current revision at some point. The last condition is based on recorded access
history, so revoking the user's group membership first does not shorten the list.

Requires a **staff** account; everyone else gets **403**. Optional `?q=` filters by name substring.
An unknown username returns **404**.

The items use a different, smaller shape than the secret list, with reformatted timestamps
(`YYYY-MM-DD HH:MM:SS`) and human-readable `type` and `status` labels:

```json
{
  "hashid": "5pG1xzxb",
  "name": "Production DB",
  "type": "Password",
  "status": "needs changing",
  "web_url": "https://teamvault.example.com/secrets/5pG1xzxb/",
  "last_changed": "2026-09-14 09:12:57",
  "last_read": "2026-09-14 09:12:57",
  "last_shared": "2026-09-14 09:12:57"
}
```

## Errors

| Status | When |
|---|---|
| 400 | Validation failed |
| 403 | Not authenticated, wrong credentials, or not permitted |
| 404 | Unknown hashid, no access to the secret, soft-deleted secret, or page out of range |
| 405 | Method not supported on that path |
| 500 | See [Gotchas](#gotchas) |

Error bodies come in three shapes, so parse defensively:

```json
{"detail": "Not found."}
{"filename": ["This field is required."]}
["Missing required field secret_data"]
```

Field errors nest for payload problems:

```json
{"secret_data": {"file_content": ["Must be a non-empty base64 encoded string."]}}
```

**403 versus 404.** A secret you are not allowed to see returns `404 {"detail": "Not found."}`,
which is deliberate: it does not reveal that the secret exists. A hashid that matches nothing
returns `404 {"detail": "No Secret matches the given query."}`. The two are distinguishable by
message, though not by status.

## Gotchas

1. **Creating a share without both keys returns 500.** The validator reads `user` and `group`
   unconditionally, so a body that omits either key raises a `KeyError` instead of a 400. Always
   send both, with one set to `null`.
2. **`status` cannot be set through the API.** On create the value is accepted but then reset,
   because storing the initial payload clears `needs_changing`. On update it is ignored outright.
   Use the web interface to flag a secret as needing a change.
3. **`data_readable` is an integer, not a boolean.** See [The Secret resource](#the-secret-resource).
4. **Files are written as `file_content` and read as `file`.**
5. **`PUT` is not a replace.** It behaves exactly like `PATCH`; fields you leave out keep their
   current values rather than being cleared.
6. **No revision history.** Only the current revision is reachable through the API.
