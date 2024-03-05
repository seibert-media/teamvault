from django.contrib.postgres.search import SearchVector
from django.core.management.base import BaseCommand

from ...models import Secret


class Command(BaseCommand):
    help = 'Update search index'

    def handle(self, *args, **options):
        secrets_total = Secret.objects.count()
        Secret.objects.all().update(
            search_index=(
                SearchVector('name', weight='A') +
                SearchVector('description', weight='B') +
                SearchVector('username', weight='C') +
                SearchVector('filename', weight='D')
            )
        )
        self.stdout.write(self.style.SUCCESS(
            "Finished updating search index for {} objects.".format(secrets_total)
        ))
