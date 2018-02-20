from django.core.management.base import BaseCommand, CommandError

from ...models import Secret


class Command(BaseCommand):
    help = 'Update search index'

    def handle(self, *args, **options):
        secrets_total = Secret.objects.count()
        secrets_processed = 0
        last_progress = 0
        for secret in Secret.objects.all():
            secret.save()
            secrets_processed += 1
            progress = int((secrets_processed / secrets_total) * 100)
            if progress > last_progress:
                self.stdout.write("{}%".format(progress))
                last_progress = progress

        self.stdout.write(self.style.SUCCESS(
            "Finished updating search index for {} objects.".format(secrets_total)
        ))
