# Secrets API — Listing, Filtering & Ordering

How to authenticate against the TeamVault REST API and query the secrets list
endpoint with filters and ordering.

## Base URL

```
https://<your-teamvault-host>/api/
```

All paths below are relative to that prefix, e.g. `GET /api/secrets/`.

## Authentication

The API uses **HTTP Basic Auth** with your TeamVault **username and password**:

```
Authorization: Basic base64(username:password)
```

Every endpoint requires authentication (`IsAuthenticated`); unauthenticated
requests get `401 Unauthorized`.

> **Note on Google sign-in.** Basic Auth validates against your *local*
> TeamVault password. If your account signs in through Google SSO and has no
> local password set, Basic Auth will fail with `401` — ask an administrator to
> set a password on your account, or call the API from a browser session
> (session-cookie auth) instead.

### Examples

**curl**

```bash
curl -u "username:password" https://teamvault.example.com/api/secrets/
```

**Python (`requests`)**

```python
import requests

BASE = 'https://teamvault.example.com'
AUTH = ('username', 'password')

r = requests.get(f'{BASE}/api/secrets/', auth=AUTH)
r.raise_for_status()
print(r.json())
```

## Listing secrets

```
GET /api/secrets/
```

Returns only secrets **visible to the authenticated user** (those that are
discoverable/public or explicitly shared with you; deleted secrets are never
returned).

### Response shape

Results are paginated (`PageNumberPagination`, **25 per page**):

```json
{
  "count": 42,
  "next": "https://teamvault.example.com/api/secrets/?page=2",
  "previous": null,
  "results": [
    {
      "api_url": "https://teamvault.example.com/api/secrets/aB3dE7gH/",
      "web_url": "https://teamvault.example.com/secrets/aB3dE7gH/",
      "name": "production-db",
      "description": "",
      "username": "app",
      "url": "https://db.example.com",
      "content_type": "password",
      "status": "ok",
      "access_policy": "discoverable",
      "needs_changing_on_leave": true,
      "created": "2026-01-15T09:30:00Z",
      "created_by": "alice",
      "last_read": "2026-06-18T08:00:00Z",
      "current_revision": "https://teamvault.example.com/api/secret-revisions/xY9z/",
      "data_readable": true
    }
  ]
}
```

`data_readable` indicates whether *you* may read the secret's actual data
(password/file/card). The list never contains the secret value itself — fetch
it via `current_revision` → `…/data`.

Get the next page with `?page=N`.

## Filtering

Pass filters as query parameters. Combining multiple filters is **AND**
(all must match). Filters only ever narrow the set of secrets you can already see.

| Parameter                 | Type                | Matching        | Example                          |
| ------------------------- | ------------------- | --------------- | -------------------------------- |
| `name`                    | string              | case-insensitive *contains* | `?name=prod`         |
| `url`                     | string              | case-insensitive *contains* | `?url=example.com`   |
| `username`                | string              | case-insensitive *contains* | `?username=app`      |
| `created_by`              | string (username)   | case-insensitive *contains* | `?created_by=alice`  |
| `content_type`            | choice              | exact           | `?content_type=password`         |
| `status`                  | choice              | exact           | `?status=ok`                     |
| `access_policy`           | choice              | exact           | `?access_policy=hidden`          |
| `needs_changing_on_leave` | boolean             | exact           | `?needs_changing_on_leave=true`  |

### Allowed choice values

| Parameter        | Values                                      |
| ---------------- | ------------------------------------------- |
| `content_type`   | `password`, `cc`, `file`                    |
| `status`         | `ok`, `needs_changing`                      |
| `access_policy`  | `any`, `discoverable`, `hidden`             |

Notes:

- `status=deleted` is **rejected with `400`** — deleted secrets are never
  listed, so it is not a selectable value.
- Any other unknown choice value also returns `400 Bad Request`.
- `created_by`, `name`, `url`, `username` are *substring* matches — e.g.
  `created_by=admin` also matches `administrator`.

### Examples

```bash
# Password secrets that still need changing
curl -u "username:password" \
  "https://teamvault.example.com/api/secrets/?content_type=password&status=needs_changing"

# Everything created by alice with "db" in the name
curl -u "username:password" \
  "https://teamvault.example.com/api/secrets/?created_by=alice&name=db"
```

## Ordering

Use `ordering=<field>`. Prefix the field with `-` for descending order.

```
GET /api/secrets/?ordering=name        # A → Z
GET /api/secrets/?ordering=-created     # newest first
```

Allowed ordering fields:

| Field          | Meaning                          |
| -------------- | -------------------------------- |
| `name`         | secret name                      |
| `created`      | creation time                    |
| `last_changed` | last time the secret was changed |
| `last_read`    | last time the secret was read    |

Any other field is ignored/rejected. Ordering is stable across pages (ties are
broken deterministically), so paging never skips or duplicates rows.

## Full-text search

Independent of the filters above, `search` runs TeamVault's search over name,
URL, username, filename and full-text index:

```
GET /api/secrets/?search=database
```

`search` can be combined with `ordering` and the filters:

```bash
curl -u "username:password" \
  "https://teamvault.example.com/api/secrets/?search=database&status=ok&ordering=-last_read"
```

## Putting it together (Python)

```python
import requests

BASE = 'https://teamvault.example.com'
AUTH = ('username', 'password')


def list_secrets(**params):
    """Yield every secret across all pages, applying filters/ordering."""
    url = f'{BASE}/api/secrets/'
    while url:
        r = requests.get(url, params=params, auth=AUTH)
        r.raise_for_status()
        body = r.json()
        yield from body['results']
        url, params = body['next'], None  # 'next' already carries the params


# Stale password secrets, oldest-read first
for secret in list_secrets(
    content_type='password',
    status='needs_changing',
    ordering='last_read',
):
    print(secret['name'], secret['last_read'])
```

## Quick reference

| Query param                 | Purpose                                            |
| --------------------------- | -------------------------------------------------- |
| `name` / `url` / `username` | substring filter (case-insensitive)               |
| `created_by`                | substring filter on creator's username            |
| `content_type`              | `password` \| `cc` \| `file`                       |
| `status`                    | `ok` \| `needs_changing`                           |
| `access_policy`             | `any` \| `discoverable` \| `hidden`                |
| `needs_changing_on_leave`   | `true` \| `false`                                  |
| `ordering`                  | `name`, `created`, `last_changed`, `last_read` (prefix `-` for desc) |
| `search`                    | full-text search term                              |
| `page`                      | page number (25 results per page)                  |