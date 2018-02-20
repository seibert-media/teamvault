from random import choice
from string import ascii_letters, digits, punctuation

from django.conf import settings
from django.core.files.uploadhandler import MemoryFileUploadHandler, StopUpload


def generate_password(length=12, alphanum=False):
    """
    Returns a password of the given length.
    """
    char_pool = ascii_letters + digits
    if not alphanum:
        char_pool += punctuation
    return "".join(choice(char_pool) for i in range(length))


class CappedMemoryFileUploadHandler(MemoryFileUploadHandler):
    def receive_data_chunk(self, raw_data, start):
        if start + len(raw_data) > settings.TEAMVAULT_MAX_FILE_SIZE:
            raise StopUpload(connection_reset=True)
        super(CappedMemoryFileUploadHandler, self).receive_data_chunk(raw_data, start)
