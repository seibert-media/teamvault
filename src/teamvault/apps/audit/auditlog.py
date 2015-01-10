from logging import getLogger

from .models import LogEntry


AUDIT_LOG = getLogger(__name__)


def log(
    msg,
    level='info',
    actor=None,
    secret=None,
    secret_revision=None,
    group=None,
    user=None,
):
    getattr(AUDIT_LOG, level)(msg)
    entry = LogEntry()
    entry.message = msg
    entry.actor = actor
    entry.secret = secret
    entry.secret_revision = secret_revision
    entry.group = group
    entry.user = user
    entry.save()
