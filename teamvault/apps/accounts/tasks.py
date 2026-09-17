import logging
from base64 import b64encode

import requests
from huey.contrib.djhuey import task

from .models import UserProfile

logger = logging.getLogger(__name__)

AVATAR_TIMEOUT = (5, 10)


@task(retries=2, retry_delay=60)
def store_avatar(user_id: int, url: str):
    """
    Download an avatar and store it on the user's profile.
    Runs outside the normal login pipeline so that we don't block the main thread.
    """
    try:
        response = requests.get(url, timeout=AVATAR_TIMEOUT)
    except requests.RequestException:
        logger.warning('Fetching avatar from %s failed for user id %s', url, user_id)
        return

    if not response.ok:
        logger.warning('Fetching avatar from %s failed for user id %s: HTTP %s', url, user_id, response.status_code)
        return

    profile = UserProfile.objects.get_or_create(user_id=user_id)[0]
    profile.avatar = b64encode(response.content)
    profile.save(update_fields=['avatar'])
