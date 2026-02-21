import json
import random
from datetime import timedelta
from hashlib import sha256

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand
from django.utils import timezone

from teamvault.apps.secrets.enums import ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret, SecretRevision, SharedSecretData

User = get_user_model()


class Command(BaseCommand):
    help = 'Create fake users and secrets'

    def handle(self, *args, **kwargs):  # noqa: ARG002
        from faker import Faker

        fake = Faker()
        fernet = self._get_fernet()
        if fernet is None:
            return

        groups = self._create_groups(fake)
        users = self._create_users(fake, groups)
        self._create_secrets(fake, fernet, users, groups)

    def _get_fernet(self):
        secret_key = getattr(settings, 'TEAMVAULT_SECRET_KEY', None)
        if not secret_key:
            self.stderr.write(self.style.ERROR('TEAMVAULT_SECRET_KEY is not set in settings.'))
            return None

        try:
            return Fernet(secret_key)
        except Exception as exc:
            self.stderr.write(self.style.ERROR(f'Invalid TEAMVAULT_SECRET_KEY: {exc}'))
            return None

    def _create_groups(self, fake, count=5):
        groups = []
        for _ in range(count):
            group_name = fake.unique.word().capitalize()
            group, _created = Group.objects.get_or_create(name=group_name)
            groups.append(group)
        self.stdout.write(self.style.SUCCESS(f'Created {len(groups)} groups.'))
        return groups

    def _create_users(self, fake, groups, count=50):
        users = []
        for _ in range(count):
            try:
                username = fake.unique.user_name()
                email = fake.unique.email()
                password = fake.password(length=12)
                user = User.objects.create_user(username=username, email=email, password=password)
                # Optionally, assign user to random groups
                if groups:
                    user_groups = random.sample(groups, k=random.randint(0, len(groups)))
                    user.groups.set(user_groups)
                user.save()
                users.append(user)
            except Exception as exc:
                self.stderr.write(self.style.ERROR(f'Error creating user: {exc}'))
        self.stdout.write(self.style.SUCCESS(f'Created {count} fake users.'))
        return users

    def _create_secrets(self, fake, fernet, users, groups):
        for user in users:
            for _ in range(10):
                try:
                    secret_name = fake.unique.word().capitalize()
                    description = fake.sentence(nb_words=10)
                    url = fake.url()
                    username_field = fake.user_name()
                    # Create the Secret object
                    secret = Secret.objects.create(
                        name=secret_name,
                        description=description,
                        url=url,
                        username=username_field,
                        content_type=ContentType.PASSWORD,
                        created_by=user,
                        status=SecretStatus.OK,
                    )
                    # Optionally, share the secret with random groups/users
                    if groups and random.choice([True, False]):
                        group = random.choice(groups)
                        SharedSecretData.objects.create(
                            group=group,
                            secret=secret,
                            grant_description='Shared via fake data script',
                            granted_by=user,
                            granted_until=timezone.now() + timedelta(days=30),
                        )
                    # Create a SecretRevision
                    plaintext_password = fake.password(length=12)
                    plaintext_data = {'password': plaintext_password}
                    plaintext_data_json = json.dumps(plaintext_data)
                    plaintext_data_sha256 = sha256(plaintext_data_json.encode('utf-8')).hexdigest()
                    encrypted_data = fernet.encrypt(plaintext_data_json.encode('utf-8'))
                    secret_revision = SecretRevision.objects.create(
                        secret=secret,
                        set_by=user,
                        encrypted_data=encrypted_data,
                        length=len(plaintext_password),
                        plaintext_data_sha256=plaintext_data_sha256,
                    )
                    # Assign the current_revision
                    secret.current_revision = secret_revision
                    secret.last_changed = timezone.now()
                    secret.last_read = timezone.now()
                    secret.save()
                except Exception as exc:
                    self.stderr.write(self.style.ERROR(f'Error creating secret for user {user.username}: {exc}'))
        self.stdout.write(self.style.SUCCESS('Created secrets and secret revisions for all users.'))
