from base64 import b64encode
from hashlib import md5

import requests


def save_gravatar(user, *_args, **_kwargs):
    email_hash = md5(user.email.strip().lower().encode("utf-8")).hexdigest()
    resp = requests.get(f'https://gravatar.com/avatar/{email_hash}?s=200&r=g&d=mp')
    if resp.ok:
        user.profile.avatar = b64encode(resp.content)
        user.profile.save()


def save_google_avatar(response, user, *_args, **_kwargs):
    resp = requests.get(response['picture'])
    if resp.ok:
        user.profile.avatar = b64encode(resp.content)
        user.profile.save()
