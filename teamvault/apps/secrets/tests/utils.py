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

_DEFAULT_PAYLOADS = {
    ContentType.PASSWORD: {'password': 'initial‑pw'},
    ContentType.CC: {
        'holder': 'Jane Doe',
        'number': '4111111111111111',
        'expiration_month': '12',
        'expiration_year': '2030',
        'security_code': '123',
        'password': '',
    },
    ContentType.FILE: {'file_content': b64encode(b'hello-from-bytes').decode('ascii')},
}


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
    content_type: ContentType = ContentType.PASSWORD,
    payload: dict | None = None,
    **kwargs,
) -> Secret:
    """Create a secret of the given content type with a sensible default payload."""
    fields = {
        'name': kwargs.get('name', 'Test Secret'),
        'created_by': owner,
        'content_type': content_type,
        'access_policy': kwargs.get('access_policy', AccessPolicy.DISCOVERABLE),
        'status': SecretStatus.OK,
    }
    if content_type == ContentType.FILE:
        fields['filename'] = kwargs.get('filename', 'hello.bin')
    secret = Secret.objects.create(**fields)
    RevisionService.save_payload(
        secret=secret,
        actor=owner,
        payload=payload if payload is not None else _DEFAULT_PAYLOADS[content_type],
        skip_acl=True,
    )
    # Give the owner permanent share so they can delegate
    SharedSecretData.objects.create(secret=secret, user=owner)
    return secret
