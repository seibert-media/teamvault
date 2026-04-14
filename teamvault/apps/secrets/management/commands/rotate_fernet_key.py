from hashlib import sha1

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from teamvault.apps.secrets.models import SecretRevision
from teamvault.apps.settings.models import Setting

BATCH_SIZE = 500


class Command(BaseCommand):
    help = 'Re-encrypt all secret revisions with the current fernet_key after a key rotation.'
    requires_system_checks = []

    def add_arguments(self, parser):  # noqa: PLR6301
        parser.add_argument(
            'old_key',
            help='The previous fernet_key that was used to encrypt existing data.',
        )

    def handle(self, *args, **options):  # noqa: ARG002
        old_key = options['old_key']
        new_key = settings.TEAMVAULT_SECRET_KEY

        try:
            old_fernet = Fernet(old_key)
        except Exception as exc:
            raise CommandError(f'Invalid old key: {exc}') from exc

        try:
            new_fernet = Fernet(new_key)
        except Exception as exc:
            raise CommandError(f'Invalid new key (from config): {exc}') from exc

        total = SecretRevision.objects.count()
        if total == 0:
            self.stdout.write('No revisions to re-encrypt.')

            # still change hash - this can happen when there are no secrets in the database
            Setting.set('fernet_key_hash', sha1(new_key.encode('utf-8')).hexdigest())
            return

        self.stdout.write(f'Re-encrypting {total} revisions in batches of {BATCH_SIZE}...')

        with transaction.atomic():
            re_encrypted = 0
            queryset = SecretRevision.objects.only('pk', 'encrypted_data').order_by('pk')
            last_pk = 0

            while True:
                batch = list(queryset.filter(pk__gt=last_pk)[:BATCH_SIZE])
                if not batch:
                    break

                for revision in batch:
                    try:
                        plaintext = old_fernet.decrypt(revision.encrypted_data)
                    except Exception as exc:
                        raise CommandError(
                            f'Failed to decrypt revision pk={revision.pk}: {exc}. No changes have been made.'
                        ) from exc
                    revision.encrypted_data = new_fernet.encrypt(plaintext)

                SecretRevision.objects.bulk_update(batch, ['encrypted_data'], batch_size=BATCH_SIZE)

                re_encrypted += len(batch)
                last_pk = batch[-1].pk
                self.stdout.write(f'  {re_encrypted}/{total} done')

            Setting.set('fernet_key_hash', sha1(new_key.encode('utf-8')).hexdigest())

        self.stdout.write(self.style.SUCCESS(f'Finished. Re-encrypted {re_encrypted} revisions.'))
