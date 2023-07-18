from datetime import timedelta
from django.utils import timezone

from teamvault.apps.secrets.models import Secret, SharedSecretData
from teamvault.apps.audit.models import LogEntry
from django.conf import settings

from teamvault.apps.secrets.utils import send_mail

all_secrets = Secret.objects.all().prefetch_related('allowed_users')


def delete_expired_shares():
    expired_secret_shares = SharedSecretData.objects.with_expiry_state().filter(is_expired=True)
    expired_secret_shares.delete()


def revoke_unused_access():
    time_threshold = timedelta(days=int(settings.DAYS_UNTIL_ACCESS_REVOKE))  # Adjust as needed
    secret_shares = SharedSecretData.objects.with_expiry_state().all().exclude(is_expired=True)
    cutoff_time = timezone.now() - time_threshold

    # Revoke access for users
    for user_share in secret_shares.users():
        last_access_time = get_last_access_time([user_share.user], user_share.secret)
        if last_access_time and last_access_time < cutoff_time:
            user_share.delete()
            send_mail([user_share.user], f'Access revoked for {user_share.secret.name}', 'secrets/mail',
                      context={'name': user_share.user.last_name, 'secret_name': user_share.secret.name})
    # Revoke access for groups
    for group_share in secret_shares.groups():
        last_access_time = get_last_access_time(group_share.group.user_set.all(), group_share.secret)
        if last_access_time and last_access_time < cutoff_time:
            group_share.delete()
            # Iterating through users because it is easier to pass the right context this way
            for user in group_share.group.user_set.all():
                send_mail([user], f'Access revoked for {group_share.secret.name}',
                          'secrets/mail',
                          context={'name': user.last_name, 'secret_name': group_share.secret.name})


def get_last_access_time(users, secret):
    # Get the most recent log entry for this user and secret
    log_entry = LogEntry.objects.filter(actor__in=users, secret=secret).order_by('-time').first()

    # If there is no log entry (i.e., the user has never accessed the secret), return None
    if log_entry is None:
        return None

    return log_entry.time
