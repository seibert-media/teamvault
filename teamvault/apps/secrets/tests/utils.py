from base64 import b64encode

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model

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

User = get_user_model()


def make_user(username: str, superuser=False):
    return User.objects.create_user(
        username=username,
        email=f'{username}@example.com',
        password='pw',
        is_superuser=superuser,
        is_staff=superuser,
    )


def new_secret(
    owner: User,
    *,
    name: str = 'Test Secret',
    content_type: ContentType = ContentType.PASSWORD,
    access_policy: AccessPolicy = AccessPolicy.DISCOVERABLE,
    share_with_owner: bool = True,
) -> Secret:
    """Creates a secret with minimal required data. Defaults to PASSWORD type."""
    secret = Secret.objects.create(
        name=name,
        created_by=owner,
        content_type=content_type,
        access_policy=access_policy,
        status=SecretStatus.OK,
    )
    if content_type == ContentType.PASSWORD:
        payload = {'password': 'initial‑pw'}
    elif content_type == ContentType.CC:
        payload = {
            'holder': 'Test User',
            'number': '4111111111111111',
            'expiration_month': '12',
            'expiration_year': '2030',
            'security_code': '123',
            'password': '',
        }
    else:
        # RevisionService uses json.dumps internally — bytes are not serialisable
        payload = {'filename': 'test.txt', 'file_content': b64encode(b'hello').decode('ascii')}
    RevisionService.save_payload(secret=secret, actor=owner, payload=payload, skip_acl=True)
    if share_with_owner:
        SharedSecretData.objects.create(secret=secret, user=owner)
    return secret
