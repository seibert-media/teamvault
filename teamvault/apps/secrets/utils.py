import base64
import re
import secrets
import string
from urllib.parse import parse_qs, urlparse

from django.core.exceptions import ValidationError
from django.core.files.uploadhandler import MemoryFileUploadHandler, SkipFile
from django.utils.translation import gettext_lazy as _

from teamvault.apps.secrets.enums import ContentType
from teamvault.apps.secrets.models import Secret, SecretChange
from teamvault.apps.secrets.validators import is_valid_otp_secret

META_FIELDS = (
    'name',
    'description',
    'username',
    'url',
    'filename',
    'access_policy',
    'needs_changing_on_leave',
    'status',
)


# What providers put between the blocks of a base32 secret so humans can read
# it: whitespace, the block separators, and the zero-width/bidi characters web
# pages insert so a long key wraps. Deliberately a blocklist — stripping
# everything outside the base32 alphabet instead would turn a mistyped password
# into a decodable secret, and the user would be locked out with no error.
_OTP_SECRET_DECORATION = re.compile(r'[\s\u00ad\u200b-\u200f\u2060\ufeff\-_]')


def normalize_otp_secret(secret: str) -> str:
    """Reduce a displayed OTP secret to the bare base32 payload.

    Trailing '=' has to go too: pyotp re-derives the padding from the
    length, so an already-padded secret ends up double-padded and fails
    to decode.
    """
    return _OTP_SECRET_DECORATION.sub('', secret).rstrip('=')


def extract_otp_params(otp_key_data: str) -> dict:
    """Parse an otp_key_data query string, with the secret normalized."""
    params = {key: values[0] for key, values in parse_qs(urlparse(otp_key_data).query).items()}
    if 'secret' in params:
        params['secret'] = normalize_otp_secret(params['secret'])
    return params


def otp_payload_fields(otp_key_data: str) -> dict:
    """Map a pasted otp_key_data URI onto the payload fields we store.

    Every write path goes through here, so the web form and the API normalize
    and reject identically. Raises ValidationError on anything that could not
    produce codes; callers that need a non-Django error translate it.
    """
    try:
        params = extract_otp_params(otp_key_data)
    except Exception as exc:
        raise ValidationError(_('OTP key should have a format like this: ___?secret=___&digits=___ ...')) from exc

    secret = params.get('secret', '')
    is_valid_otp_secret(secret)
    if not secret:
        # Without a seed the remaining parameters cannot produce a code, so
        # storing them would leave a revision that only looks like it has OTP.
        return {}

    fields = {'otp_key': secret}
    for param in ('digits', 'algorithm'):
        if params.get(param):
            fields[param] = params[param]
    return fields


def copy_meta_from_secret(secret: Secret) -> dict:
    return {
        'name': secret.name,
        'description': secret.description,
        'username': secret.username,
        'url': secret.url,
        'filename': secret.filename,
        'access_policy': int(secret.access_policy),
        'needs_changing_on_leave': secret.needs_changing_on_leave,
        'status': int(secret.status),
    }


def apply_snapshot_to_secret(secret: Secret, change: SecretChange) -> list[str]:
    """Apply metadata snapshot fields from a SecretChange onto a Secret.
    Returns the list of fields that changed.
    """
    dirty = []
    for f in META_FIELDS:
        val = getattr(change, f)
        if getattr(secret, f) != val:
            setattr(secret, f, val)
            dirty.append(f)
    return dirty


def serialize_add_edit_data(cleaned_data, secret):
    plaintext_data = {}
    if secret.content_type == ContentType.PASSWORD:
        if cleaned_data.get('password'):
            plaintext_data['password'] = cleaned_data['password']
        plaintext_data.update(otp_payload_fields(cleaned_data['otp_key_data']))
    elif secret.content_type == ContentType.FILE:
        file = cleaned_data.get('file')
        if not file:
            return plaintext_data

        try:
            plaintext_data['file_content'] = base64.b64encode(file.read()).decode()
        except Exception as e:
            raise ValidationError('File type not supported') from e

        if hasattr(file, 'name') and file.name:
            secret.filename = file.name
            secret.save()
    elif secret.content_type == ContentType.CC:
        plaintext_data = {
            'holder': cleaned_data['holder'],
            'number': cleaned_data['number'],
            'expiration_month': str(cleaned_data['expiration_month']),
            'expiration_year': str(cleaned_data['expiration_year']),
            'security_code': str(cleaned_data['security_code']),
            'password': cleaned_data['password'],
        }
    return plaintext_data


def generate_password(length, digits, upper, lower, special):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = []
    password.extend(secrets.choice(string.digits) for _ in range(digits))
    password.extend(secrets.choice(string.ascii_lowercase) for _ in range(lower))
    password.extend(secrets.choice(string.ascii_uppercase) for _ in range(upper))
    password.extend(secrets.choice(string.punctuation) for _ in range(special))

    # Fill the rest of the lenght with random characters from all types
    password.extend(secrets.choice(characters) for _ in range(length - len(password)))

    # Randomly shuffle the characters, so they're not grouped by type
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)


class CappedMemoryFileUploadHandler(MemoryFileUploadHandler):
    def receive_data_chunk(self, raw_data, start):
        if not self.activated:  # if the file size is too big, this handler will not be activated
            # if we use StopUpload here, forms will not get fully validated,
            # which leads to more form errors than we prefer
            # raise StopUpload(connection_reset=True)
            raise SkipFile()
        super().receive_data_chunk(raw_data, start)
