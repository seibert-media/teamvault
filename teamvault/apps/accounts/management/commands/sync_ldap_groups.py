from django.core.management.base import BaseCommand
from teamvault.apps.accounts.management.commands._ldap_sync import ldap_sync_enabled
from teamvault.apps.accounts.tasks import sync_ldap_groups


class Command(BaseCommand):
    help = 'Syncs the members of all LDAP-backed groups with LDAP. Also runs periodically via huey.'

    def handle(self, *args, **options):  # noqa: ARG002
        if not ldap_sync_enabled(self):
            self.stdout.write(self.style.ERROR('LDAP sync not enabled.'))
            return
        sync_ldap_groups()
        self.stdout.write(self.style.SUCCESS('Done.'))
