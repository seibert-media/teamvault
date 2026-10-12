import hmac
from base64 import urlsafe_b64decode
from hashlib import sha256
from json import dumps
from typing import Any

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

_HKDF_INFO = b'teamvault secret revision fingerprint'


def _mac_key(fernet_key: str | bytes) -> bytes:
    if isinstance(fernet_key, str):
        fernet_key = fernet_key.encode('ascii')
    raw_key = urlsafe_b64decode(fernet_key)
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(raw_key)


def payload_fingerprint(secret_id: int, payload: Any, fernet_key: str | bytes | None = None) -> str:
    """Returns the hex HMAC-SHA256 fingerprint of `payload` within `secret_id`."""

    if fernet_key is None:
        fernet_key = settings.TEAMVAULT_SECRET_KEY
    message = f'{secret_id}\n'.encode() + dumps(payload, sort_keys=True).encode()
    return hmac.new(_mac_key(fernet_key), message, sha256).hexdigest()
