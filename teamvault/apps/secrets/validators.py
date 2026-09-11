import hashlib
from dataclasses import dataclass

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
DEFAULT_OTP_DIGITS = 6


@dataclass(frozen=True)
class OTPParams:
    otp_key: str
    digits: int
    algorithm: str


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


def otp_digest(algorithm: str):
    return OTP_DIGESTS[normalize_otp_algorithm(algorithm)]


def get_otp_params_from_payload(payload: object) -> OTPParams:
    if not isinstance(payload, dict):
        raise ValidationError(_('This secret has no OTP key.'))

    otp_key = payload.get('otp_key')
    if not isinstance(otp_key, str) or not otp_key:
        raise ValidationError(_('This secret has no OTP key.'))

    try:
        digits = int(payload.get('digits') or DEFAULT_OTP_DIGITS)
    except (TypeError, ValueError) as exc:
        raise ValidationError(_('This secret has an invalid OTP digit count.')) from exc

    # Revisions written before the algorithm was saved just assume SHA1.
    algorithm = payload.get('algorithm') or DEFAULT_OTP_ALGORITHM
    return OTPParams(otp_key=otp_key, digits=digits, algorithm=algorithm)
