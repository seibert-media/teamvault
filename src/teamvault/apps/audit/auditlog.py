from logging import getLogger

from .models import LogEntry


# TODO rename and add file handler
AUDIT_LOG = getLogger(__name__)


def log(
    msg,
    level='info',
    actor=None,
    password=None,
    password_revision=None,
    group=None,
    user=None,
):
    getattr(AUDIT_LOG, level)(msg)
    entry = LogEntry()
    entry.message = msg
    entry.actor = actor
    entry.password = password
    entry.password_revision = password_revision
    entry.group = group
    entry.user = user
    entry.save()
