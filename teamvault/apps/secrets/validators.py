from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from pyotp import TOTP


def is_valid_otp_secret(value):
    try:
        TOTP(value).byte_secret()
    except Exception:
        raise ValidationError(_('OTP key has wrong format. Please enter a valid OTP key.'))
