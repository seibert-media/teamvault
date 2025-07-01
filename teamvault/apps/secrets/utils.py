import base64
import secrets
import string
from urllib.parse import urlparse, parse_qs

from django.core.files.uploadhandler import MemoryFileUploadHandler, SkipFile

from .models import Secret


def extract_url_and_params(data):
    data_as_url = urlparse(data)
    data_params = parse_qs(data_as_url.query)
    for key, value in data_params.items():
        data_params[key] = value[0]
    return data_as_url, data_params


def serialize_add_edit_data(cleaned_data, secret):
    plaintext_data = {}
    if secret.content_type == Secret.CONTENT_PASSWORD:
        cleaned_data_as_url, data_params = extract_url_and_params(cleaned_data["otp_key_data"])
        if cleaned_data.get("password"):
            plaintext_data['password'] = cleaned_data['password']
        for attr in ['secret', 'digits', 'algorithm']:
            if data_params.get(attr):
                if attr == 'secret':
                    plaintext_data['otp_key'] = data_params[attr]
                else:
                    plaintext_data[attr] = data_params[attr]
    elif secret.content_type == Secret.CONTENT_FILE:
        try:
            plaintext_data['file_content'] = base64.b64encode(cleaned_data['file'].read()).decode()
            secret.filename = cleaned_data['file'].name
            secret.save()
        except Exception as e:
            raise ('File type not suported', e)
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
