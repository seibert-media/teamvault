from teamvault.apps.accounts.management.commands.sync_user_uuids import Command as SyncUserUUIDsCommand


class Command(SyncUserUUIDsCommand):
    """Deprecated alias kept so existing admin scripts keep working."""

    help = 'Deprecated alias for sync_user_uuids.'

    def handle(self, *args, **options):
        self.stderr.write('sync_entry_uuids is deprecated, use sync_user_uuids instead.')
        super().handle(*args, **options)
