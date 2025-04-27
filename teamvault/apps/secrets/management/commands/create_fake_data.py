import json
import random
from datetime import timedelta
from hashlib import sha256

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from django.contrib.auth.models import User, Group
from teamvault.apps.secrets.models import Secret, SecretRevision, SharedSecretData


class Command(BaseCommand):
    help = 'Create fake users and secrets'

    def handle(self, *args, **kwargs):
        from faker import Faker

        fake = Faker()
        if not hasattr(settings, 'TEAMVAULT_SECRET_KEY'):
            self.stderr.write(self.style.ERROR('TEAMVAULT_SECRET_KEY is not set in settings.'))
            return

        try:
            fernet = Fernet(settings.TEAMVAULT_SECRET_KEY)
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Invalid TEAMVAULT_SECRET_KEY: {e}'))
            return

        groups = []
        for _ in range(5):
            group_name = fake.unique.word().capitalize()
            group, created = Group.objects.get_or_create(name=group_name)
            groups.append(group)
        self.stdout.write(self.style.SUCCESS(f'Created {len(groups)} groups.'))

        # Create 50 fake users
        users = []
        for _ in range(50):
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
            except Exception as e:
                self.stderr.write(self.style.ERROR(f'Error creating user: {e}'))
        self.stdout.write(self.style.SUCCESS('Created 50 fake users.'))

        # Create secrets for each user
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
                        content_type=Secret.CONTENT_PASSWORD,
                        created_by=user,
                        status=Secret.STATUS_OK,
                    )
                    # Optionally, share the secret with random groups/users
                    if groups and random.choice([True, False]):
                        group = random.choice(groups)
                        SharedSecretData.objects.create(
                            group=group,
                            secret=secret,
                            grant_description='Shared via fake data script',
                            granted_by=user,
                            granted_until=timezone.now() + timedelta(days=30)
                        )
                    # Create a SecretRevision
                    plaintext_password = fake.password(length=12)
                    plaintext_data = {
                        'password': plaintext_password
                    }
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
                except Exception as e:
                    self.stderr.write(self.style.ERROR(f'Error creating secret for user {user.username}: {e}'))
        self.stdout.write(self.style.SUCCESS('Created secrets and secret revisions for all users.'))
