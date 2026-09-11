import hashlib

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from pyotp import TOTP

OTP_DIGESTS = {
    # As defined in RFC 6238
    'SHA1': hashlib.sha1,
    'SHA256': hashlib.sha256,
    'SHA512': hashlib.sha512,
}
DEFAULT_OTP_ALGORITHM = 'SHA1'


def is_valid_otp_secret(value):
    try:
        TOTP(value).byte_secret()
    except Exception as exc:
        raise ValidationError(_('OTP key has wrong format. Please enter a valid OTP key.')) from exc


def normalize_otp_algorithm(algorithm: str) -> str:
    normalized = algorithm.strip().upper()
    if normalized not in OTP_DIGESTS:
        raise ValidationError(
            _('OTP algorithm %(algorithm)s is not supported. Supported algorithms: %(supported)s.')
            % {'algorithm': algorithm, 'supported': ', '.join(OTP_DIGESTS)}
        )
    return normalized


def otp_digest(algorithm: str | None):
    """Map a stored algorithm onto the hash to generate codes with.

    Revisions written before the algorithm was captured just assume SHA1.
    """
    if not algorithm:
        return OTP_DIGESTS[DEFAULT_OTP_ALGORITHM]
    return OTP_DIGESTS[normalize_otp_algorithm(algorithm)]
