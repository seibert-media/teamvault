from cryptography.fernet import Fernet
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Generate a new Fernet key for use in teamvault.cfg.'

    def handle(self, *args, **options):  # noqa: ARG002
        self.stdout.write(Fernet.generate_key().decode())
