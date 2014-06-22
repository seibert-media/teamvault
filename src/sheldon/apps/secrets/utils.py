from random import choice
from string import digits, letters, punctuation

from cryptography.fernet import Fernet
from django.conf import settings


def generate_password(length=12, alphanum=False):
    """
    Returns a password of the given length.
    """
    char_pool = letters + digits
    if not alphanum:
        char_pool += punctuation
    return "".join(choice(char_pool) for i in range(length))


def decrypt(secret):
    f = Fernet(settings.SHELDON_SECRET)
    return f.decrypt(secret)


def encrypt(secret):
    f = Fernet(settings.SHELDON_SECRET)
    return f.encrypt(secret)
