from random import choice
from string import ascii_letters, digits, punctuation


def generate_password(length=12, alphanum=False):
    """
    Returns a password of the given length.
    """
    char_pool = ascii_letters + digits
    if not alphanum:
        char_pool += punctuation
    return "".join(choice(char_pool) for i in range(length))
