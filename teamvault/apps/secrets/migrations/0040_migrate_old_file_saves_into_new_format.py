import binascii
from base64 import b64decode, b64encode
from json import JSONDecodeError, dumps, loads

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import migrations


class LegacyJsonButNotBase64(Exception):
    pass


def migrate_file_secrets_to_new_save_method(apps, schema_editor):
    SecretModel = apps.get_model("secrets", "Secret")
    SecretRevisionModel = apps.get_model("secrets", "SecretRevision")

    try:
        ct_field = SecretModel._meta.get_field("content_type")
        choices = dict(ct_field.choices or ())
        file_ct = next(k for k, v in choices.items() if str(v).lower() == "file")
    except Exception:
        file_ct = 3

    key = settings.TEAMVAULT_SECRET_KEY
    fernet = Fernet(key)

    qs = SecretRevisionModel.objects.filter(secret__content_type=file_ct)

    for revision in qs.iterator():
        enc = revision.encrypted_data
        if isinstance(enc, memoryview):
            enc = enc.tobytes()
        if not isinstance(enc, (bytes, bytearray)):
            enc = bytes(enc)

        decrypted = fernet.decrypt(enc)

        try:
            payload = loads(decrypted)
            if isinstance(payload, list):
                raise LegacyJsonButNotBase64

            content = payload.get("file_content")
            if isinstance(content, str):
                try:
                    b64decode(content, validate=True)
                    continue
                except binascii.Error:
                    raw_bytes = content.encode()
            else:
                raise LegacyJsonButNotBase64

        except (JSONDecodeError, LegacyJsonButNotBase64, UnicodeDecodeError):
            raw_bytes = decrypted

        new_payload_bytes = dumps(
            {"file_content": b64encode(raw_bytes).decode("ascii")}
        ).encode("utf-8")

        revision.encrypted_data = fernet.encrypt(new_payload_bytes)
        revision.save(update_fields=["encrypted_data"])


class Migration(migrations.Migration):
    dependencies = [
        ("secrets", "0039_secretrevision_restored_from"),
    ]

    operations = [
        migrations.RunPython(
            migrate_file_secrets_to_new_save_method,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
