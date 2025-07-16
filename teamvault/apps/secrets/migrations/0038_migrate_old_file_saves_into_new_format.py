import binascii
from base64 import b64decode, b64encode
from json import JSONDecodeError, dumps, loads

from teamvault.apps.secrets.models import Secret

from cryptography.fernet import Fernet
from django.db import migrations
from django.conf import settings


class WrongVersion(Exception):
    pass


def is_v3(encrypted_data, f: Fernet):
    decrypted_data = f.decrypt(encrypted_data)
    file_content = loads(decrypted_data)['file_content'].encode()
    if b64encode(b64decode(file_content)) == file_content:
        return True
    return False


def migrate_file_secrets_to_new_save_method(apps, schema_editor):
    # Currently 3 ways secret files are stored:
    #   v1. encrypted_data is the file content f.encrypt(file_content) (0.9.2)
    #   v2. json object with .decode() 'file_content' (1.0.0 rc7)
    #   v3. json object with b64 encoded 'file_content' (1.0.0 rc8)
    Historical_Secret = apps.get_model('secrets', 'Secret')
    file_secrets = Historical_Secret.objects.filter(content_type=Secret.CONTENT_FILE)
    f = Fernet(settings.TEAMVAULT_SECRET_KEY)
    for secret in file_secrets:
        revision = secret.current_revision
        plaintext_data = f.decrypt(revision.encrypted_data)
        try:
            plaintext_data = plaintext_data.decode()
            plaintext_data = loads(plaintext_data)
            # could be json file saved directly
            if not plaintext_data.get('file_content') or len(plaintext_data) > 1:
                # secret is a json saved the old way
                # does not capture case, where user saved a json with just file_content as key
                #   -> highly unlikely though
                raise UnicodeDecodeError
            plaintext_data = plaintext_data.get('file_content')
            if b64encode(b64decode(plaintext_data)) == plaintext_data:
                # file_content has been stored the correct/new way as b64encoded
                continue
            # file has been stored as json but not b64 encoded -> file_content.decode()
            plaintext_data = plaintext_data.encode()
        except UnicodeDecodeError:
            # UnicodeDecodeError:
            #   file is stored the old way: just f.decrypt(file_content)
            #   store as json with b64 encoded file_content
            pass
        except (JSONDecodeError, binascii.Error):
            # JSONDecodeError: file has not been stored as json -> save as json with b64 encoded file_content
            # binascii Error: error when trying to check for base64 encodation
            plaintext_data = plaintext_data.encode()

        encrypted_data = f.encrypt(
            dumps({"file_content": b64encode(plaintext_data).decode()}).encode()
        )
        revision.encrypted_data = encrypted_data
        if not is_v3(encrypted_data, f):
            raise WrongVersion(
                f"Encrypted data is not consistent with v3 file secrets. Encrypted data: {encrypted_data}"
            )
        revision.save()


class Migration(migrations.Migration):
    dependencies = [
        ("secrets", "0037_change_secretrevision_plaintextdata_key_of_password_type"),
    ]

    operations = [
        migrations.RunPython(migrate_file_secrets_to_new_save_method, reverse_code=migrations.RunPython.noop),
    ]
