from datetime import timedelta
from django.utils import timezone

from teamvault.apps.secrets.models import Secret
from teamvault.apps.audit.models import LogEntry
from teamvault.settings import CONFIG

all_secrets = Secret.objects.all().prefetch_related('allowed_users')


def revoke_access():
    time_threshold = timedelta(days=int(CONFIG["teamvault"]["days_until_revoke"]))  # Adjust as needed
    cutoff_time = timezone.now() - time_threshold
    for secret in all_secrets:
        for user in secret.allowed_users.all():
            last_access_time = get_last_access_time(user, secret)
            if last_access_time and last_access_time < cutoff_time:
                secret.allowed_users.remove(user)


def get_last_access_time(user, secret):
    # Get the most recent log entry for this user and secret
    log_entry = LogEntry.objects.filter(actor=user, secret=secret).order_by('-time').first()

    # If there is no log entry (i.e., the user has never accessed the secret), return None
    if log_entry is None:
        return None

    return log_entry.time
