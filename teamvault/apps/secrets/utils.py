from random import choice
from string import ascii_letters, digits, punctuation

from django.core.files.uploadhandler import MemoryFileUploadHandler, SkipFile


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
        if not self.activated:  # if the file size is too big, this handler will not be activated
            # if we use StopUpload here, forms will not get fully validated,
            # which leads to more form errors than we prefer
            # raise StopUpload(connection_reset=True)
            raise SkipFile()
        super(CappedMemoryFileUploadHandler, self).receive_data_chunk(raw_data, start)
