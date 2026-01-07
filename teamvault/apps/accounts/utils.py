import logging
from base64 import b64encode
from hashlib import md5

import requests

from teamvault.apps.accounts.models import UserProfile, UserProfile as UserProfileModel
from teamvault.apps.audit.models import LogEntry
from teamvault.apps.secrets.models import Secret, SecretRevision, SharedSecretData

logger = logging.getLogger(__name__)


def save_gravatar(user, *_args, **_kwargs):
    email_hash = md5(user.email.strip().lower().encode('utf-8')).hexdigest()
    resp = requests.get(f'https://gravatar.com/avatar/{email_hash}?s=200&r=g&d=mp')
    if resp.ok:
        user_settings = UserProfileModel.objects.get_or_create(user=user)[0]
        user_settings.avatar = b64encode(resp.content)
        user_settings.save()


def save_google_avatar(response, user, *_args, **_kwargs):
    resp = requests.get(response['picture'])
    if resp.ok:
        user_settings = UserProfileModel.objects.get_or_create(user=user)[0]
        user_settings.avatar = b64encode(resp.content)
        user_settings.save()


def merge_users(user1, user2, dry_run=True):
    logger.info(
        'Merging user %s into %s\n'
        'Secrets & Audit Logs will be merged. User Profiles, Social Auth data and User itself will be deleted.\n'
        'Dry run: %s',
        user1.username,
        user2.username,
        dry_run,
    )

    # Secrets / SharedSecretData / SecretRevisions
    user1_secrets = SharedSecretData.objects.filter(user=user1)
    user2_secrets = SharedSecretData.objects.filter(user=user2)
    secrets_to_merge = user1_secrets.exclude(pk__in=user2_secrets.values_list('pk', flat=True))
    logger.info(
        '%s Secrets found: %s',
        secrets_to_merge.count(),
        secrets_to_merge.values_list('pk', flat=True),
    )

    user1_created = Secret.objects.filter(created_by=user1)
    logger.info(
        '%s Secrets w/ created_by found: %s',
        user1_created.count(),
        user1_created.values_list('pk', flat=True),
    )

    user1_revisions = SecretRevision.objects.filter(set_by=user1)
    logger.info(
        '%s SecretRevisions found: %s',
        user1_revisions.count(),
        user1_revisions.values_list('pk', flat=True),
    )

    # Audit Logs
    user1_actor_logs = LogEntry.objects.filter(actor=user1)
    user1_user_logs = LogEntry.objects.filter(user=user1)
    logger.info(
        '%s Actor Logs found: %s',
        user1_actor_logs.count(),
        user1_actor_logs.values_list('pk', flat=True),
    )
    logger.info(
        '%s User Logs found: %s',
        user1_user_logs.count(),
        user1_user_logs.values_list('pk', flat=True),
    )

    # User Profiles
    user1_profiles = UserProfile.objects.filter(user=user1)
    logger.info(
        '%s User Profiles found: %s',
        user1_profiles.count(),
        user1_profiles.values_list('pk', flat=True),
    )

    # User Social Auth data
    user1_social_data = user1.social_auth.all().exclude(pk__in=user2.social_auth.all().values_list('pk', flat=True))
    logger.info(
        '%s Social Auth data found: %s',
        user1_social_data.count(),
        user1_social_data.values_list('pk', flat=True),
    )

    if not dry_run:
        secrets_to_merge.update(user=user2)
        user1_created.update(created_by=user2)
        user1_revisions.update(set_by=user2)
        logger.info('Updated secrets.')

        user1_actor_logs.update(actor=user2)
        user1_user_logs.update(user=user2)
        logger.info('Updated logs.')

        user1_profiles.delete()
        logger.info('Deleted User Profiles.')

        user1_social_data.delete()
        logger.info('Deleted Social Auth data.')

        user1.delete()
        logger.info('Deleted User')
