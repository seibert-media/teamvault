from base64 import b32decode

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def is_valid_b32_string(value, casefold=False):
    try:
        b32decode(value, casefold=casefold)
    except Exception:
        raise ValidationError(_('OTP key has wrong format. Please enter a valid OTP key.'))
