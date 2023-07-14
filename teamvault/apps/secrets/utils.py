import secrets
import string

from django.core.files.uploadhandler import MemoryFileUploadHandler, SkipFile


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
        super(CappedMemoryFileUploadHandler, self).receive_data_chunk(raw_data, start)
