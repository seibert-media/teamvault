"""Access gates shared by the secrets routers: hashid lookup + v1-parity permission checks."""

from django.core.exceptions import PermissionDenied
from django.http import Http404
from ninja.errors import HttpError

from teamvault.apps.secrets.models import Secret


def readable_secret(user, hashid: str) -> Secret:
    """Fetch a secret and enforce the user's read access (404 invisible, 403 visible-but-unreadable)."""
    try:
        secret = Secret.objects.get(hashid=hashid)
    except Secret.DoesNotExist as exc:
        raise HttpError(404, f'No secret with hashid {hashid}') from exc
    try:
        secret.check_read_access(user)
    except Http404 as exc:
        raise HttpError(404, f'No secret with hashid {hashid}') from exc
    except PermissionDenied as exc:
        raise HttpError(403, 'You do not have read access to this secret') from exc
    return secret


def writable_secret(user, hashid: str) -> Secret:
    """Fetch a secret and enforce the user's write access.

    Mirrors v1's write gate exactly: the DRF detail view's get_object() runs check_read_access
    (404 invisible, 403 visible-but-unreadable), and RevisionService.save_payload then requires
    is_readable() != NOT_ALLOWED. Read access is therefore the write gate.
    """
    try:
        secret = Secret.objects.get(hashid=hashid)
    except Secret.DoesNotExist as exc:
        raise HttpError(404, f'No secret with hashid {hashid}') from exc
    try:
        secret.check_read_access(user)
    except Http404 as exc:
        raise HttpError(404, f'No secret with hashid {hashid}') from exc
    except PermissionDenied as exc:
        raise HttpError(403, 'You do not have write access to this secret') from exc
    return secret
