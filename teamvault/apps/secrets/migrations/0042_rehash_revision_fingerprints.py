from json import JSONDecodeError, loads

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import migrations

from teamvault.apps.secrets.fingerprint import payload_fingerprint

BATCH_SIZE = 500


def _decrypted_payload(fernet, revision):
    encrypted = revision.encrypted_data
    if isinstance(encrypted, memoryview):
        encrypted = encrypted.tobytes()
    plaintext = fernet.decrypt(encrypted).decode('utf-8')
    try:
        return loads(plaintext)
    except JSONDecodeError:
        return plaintext


def _merge_into(apps, survivor, duplicate):
    LogEntry = apps.get_model('audit', 'LogEntry')
    Secret = apps.get_model('secrets', 'Secret')
    SecretChange = apps.get_model('secrets', 'SecretChange')

    survivor.accessed_by.add(*duplicate.accessed_by.all())
    SecretChange.objects.filter(revision=duplicate).update(revision=survivor)
    LogEntry.objects.filter(secret_revision=duplicate).update(secret_revision=survivor)
    Secret.objects.filter(current_revision=duplicate).update(current_revision=survivor)
    duplicate.delete()


def rehash_revision_fingerprints(apps, schema_editor):
    """Replace the unsalted SHA-256 of the plaintext with the keyed fingerprint.

    Earlier code hashed the same plaintext in more than one way (bare password
    vs. JSON payload), so two rows of one secret can now map to the same
    fingerprint. Those rows are merged, keeping the oldest one.
    """
    SecretRevision = apps.get_model('secrets', 'SecretRevision')
    fernet = Fernet(settings.TEAMVAULT_SECRET_KEY)

    survivor_pk_by_fingerprint = {}
    pending = []

    def flush():
        SecretRevision.objects.bulk_update(pending, ['plaintext_data_sha256'], batch_size=BATCH_SIZE)
        pending.clear()

    revisions = SecretRevision.objects.only('pk', 'secret_id', 'encrypted_data').order_by('secret_id', 'pk')
    for revision in revisions.iterator(chunk_size=BATCH_SIZE):
        fingerprint = payload_fingerprint(revision.secret_id, _decrypted_payload(fernet, revision))
        key = (revision.secret_id, fingerprint)
        if key in survivor_pk_by_fingerprint:
            _merge_into(apps, SecretRevision.objects.get(pk=survivor_pk_by_fingerprint[key]), revision)
            continue
        survivor_pk_by_fingerprint[key] = revision.pk
        revision.plaintext_data_sha256 = fingerprint
        pending.append(revision)
        if len(pending) >= BATCH_SIZE:
            flush()
    if pending:
        flush()


class Migration(migrations.Migration):
    dependencies = [
        ('audit', '0001_initial'),
        ('secrets', '0041_fix_passwords_old_payload'),
    ]

    operations = [
        migrations.RunPython(rehash_revision_fingerprints, reverse_code=migrations.RunPython.noop),
    ]
