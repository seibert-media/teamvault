from django.contrib.auth import get_user_model
from django.urls import reverse

from teamvault.apps.secrets.models import Secret, SharedSecretData

User = get_user_model()
STATIC_TEST_KEY = b"WKGGUS52yN68AtcgOKKKqDzccS3hOy32ShZWKwDWe3Q="  # stable Fernet key for tests

def make_secret(
        owner: User, name: str = "secret", data: str = "topsecret",
        access_policy: int = Secret.ACCESS_POLICY_DISCOVERABLE, share_with_owner: bool = True, ) -> Secret:
    """
    Create a Secret like production does
    """
    s = Secret.objects.create(name=name, created_by=owner, access_policy=access_policy)
    s.set_data(owner, {"password": data}, skip_access_check=True)

    if share_with_owner:
        SharedSecretData.objects.create(secret=s, user=owner, granted_by=owner)

    return s


def get_secret_detail_url(secret):
    return reverse('secrets.secret-detail', kwargs={'hashid': secret.hashid})
