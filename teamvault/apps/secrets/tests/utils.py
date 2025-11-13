from cryptography.fernet import Fernet
from django.contrib.auth.models import User

from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.models import (
    Secret,
    SharedSecretData,
)
from teamvault.apps.secrets.services.revision import RevisionService

TEST_KEY = Fernet.generate_key()  # random key for the test run
COMMON_OVERRIDES = {
    'TEAMVAULT_SECRET_KEY': TEST_KEY,
    'HASHID_MIN_LENGTH': 8,
    'HASHID_SALT': 'test‑salt',
    'BASE_URL': 'https://test.example',
    'ALLOW_SUPERUSER_READS': True,
}


def make_user(username: str, superuser=False):
    return User.objects.create_user(
        username=username,
        email=f'{username}@example.com',
        password='pw',
        is_superuser=superuser,
        is_staff=superuser,
    )


def new_secret(owner: User, **kwargs) -> Secret:
    """Creates a password secret with minimal required data."""
    secret = Secret.objects.create(
        name=kwargs.get('name', 'Test Secret'),
        created_by=owner,
        content_type=ContentType.PASSWORD,
        access_policy=kwargs.get('access_policy', AccessPolicy.DISCOVERABLE),
        status=SecretStatus.OK,
    )
    RevisionService.save_payload(
        secret=secret,
        actor=owner,
        payload={'password': 'initial‑pw'},
        skip_acl=True
    )
    # Give the owner permanent share so they can delegate
    SharedSecretData.objects.create(secret=secret, user=owner)
    return secret



