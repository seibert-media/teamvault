from json import dumps, loads

from cryptography.fernet import Fernet
from django.db import migrations
from django.conf import settings


def change_plaintextdata_key(apps, schema_editor):
    Secret = apps.get_model('secrets', 'Secret')
    password_secrets = Secret.objects.filter(secretrevision__otp_key_set=True)
    f = Fernet(settings.TEAMVAULT_SECRET_KEY)
    for secret in password_secrets:
        plaintext_data = secret.current_revision.encrypted_data
        plaintext_data = f.decrypt(plaintext_data).decode("utf-8")
        plaintext_data = loads(plaintext_data)
        if 'secret' in plaintext_data:
            plaintext_data['otp_key'] = plaintext_data.pop('secret')
        plaintext_data = dumps(plaintext_data).encode("utf-8")
        secret.current_revision.encrypted_data = f.encrypt(plaintext_data)
        secret.current_revision.save()


class Migration(migrations.Migration):
    dependencies = [
        ("secrets", "0036_alter_secret_shared_groups_alter_secret_shared_users"),
    ]

    operations = [
        migrations.RunPython(change_plaintextdata_key, reverse_code=migrations.RunPython.noop),
    ]


