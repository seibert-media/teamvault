import binascii
from base64 import b64decode, b64encode
from json import JSONDecodeError, dumps, loads

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import migrations

from teamvault.apps.secrets.models import Secret


class LegacyJsonButNotBase64(Exception):
    pass


def migrate_file_secrets_to_new_save_method(apps, schema_editor):
    # Currently 3 ways secret files are stored:
    #   v1. encrypted_data is the file content f.encrypt(file_content) (0.9.2)
    #   v2. json object with .decode() 'file_content' (1.0.0 rc7)
    #   v3. json object with b64 encoded 'file_content' (1.0.0 rc8)
    HistoricalSecretRevisionModel = apps.get_model('secrets', 'SecretRevision')
    revisions = HistoricalSecretRevisionModel.objects.filter(secret__content_type=Secret.CONTENT_FILE)
    f = Fernet(settings.TEAMVAULT_SECRET_KEY)

    for revision in revisions:
        decrypted_data = f.decrypt(revision.encrypted_data)
        try:
            payload = loads(decrypted_data)  # doesn't need decode, works on bytes
            if isinstance(payload, list):
                # JSON can also be a list, where .get will not work
                raise LegacyJsonButNotBase64

            content = payload.get("file_content")
            if isinstance(content, str):
                # content is textual; decide whether it’s already B64
                try:
                    b64decode(content, validate=True)
                    # Already v3 – nothing to do
                    continue
                except binascii.Error:
                    # v2 – .decode() was applied; convert to bytes
                    raw_bytes = content.encode()
            else:
                # it's json but doesn't have B64 file_content
                raise LegacyJsonButNotBase64
        except (JSONDecodeError, LegacyJsonButNotBase64, UnicodeDecodeError):
            #  v1 – `decrypted` is raw bytes
            raw_bytes = decrypted_data

            # At this point raw_bytes should hold the original file bytes
        new_payload = dumps({"file_content": b64encode(raw_bytes).decode()}).encode()

        encrypted_data = f.encrypt(new_payload)
        revision.encrypted_data = encrypted_data
        revision.save()


class Migration(migrations.Migration):
    dependencies = [
        ("secrets", "0037_change_secretrevision_plaintextdata_key_of_password_type"),
    ]

    operations = [
        migrations.RunPython(migrate_file_secrets_to_new_save_method, reverse_code=migrations.RunPython.noop),
    ]
