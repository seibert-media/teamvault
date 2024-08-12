import secrets
import string
from json import dumps

from django.core.files.uploadhandler import MemoryFileUploadHandler, SkipFile

from .models import Secret


def serialize_add_edit_data(cleaned_data, secret):
    plaintext_data = {}
    if secret.content_type == Secret.CONTENT_PASSWORD:
        if cleaned_data['password']:
            plaintext_data['password'] = cleaned_data['password']
        if cleaned_data['otp_key_data']:
            plaintext_key_data = cleaned_data['otp_key_data']
            plaintext_data["opt_key"] = plaintext_key_data[
                                        plaintext_key_data.index("secret") + 7:
                                        plaintext_key_data.index("&")
                                        ].encode('utf-8')
            plaintext_data["digits"] = 8 if "digits=8" in plaintext_key_data else 6
            if "SHA256" in plaintext_key_data:
                algorithm = "SHA256"
            elif "SHA512" in plaintext_key_data:
                algorithm = "SHA512"
            else:
                algorithm = "SHA1"
            plaintext_data["algorithm"] = algorithm
    elif secret.content_type == Secret.CONTENT_FILE:
        plaintext_data["file_content"] = cleaned_data['file'].read()
        secret.filename = cleaned_data['file'].name
        secret.save()
    elif secret.content_type == Secret.CONTENT_CC:
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
        super(CappedMemoryFileUploadHandler, self).receive_data_chunk(raw_data, start)
