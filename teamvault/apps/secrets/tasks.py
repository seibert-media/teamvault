from datetime import timedelta

import logging

from ..audit.auditlog import log
from ..audit.models import LogEntry, AuditLogCategoryChoices
from ..secrets.models import SharedSecretData

from django.conf import settings
from django.contrib.auth.models import Group
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from huey import crontab
from huey.contrib.djhuey import periodic_task


huey_log = logging.getLogger('huey')


@periodic_task(crontab(**settings.HUEY_TASKS['scheduler_frequency']))
def prune_expired_shares():
    for share in SharedSecretData.objects.with_expiry_state().filter(is_expired=True):
        huey_log.info(
            _("Removing expired share of '{secret}' ({secret_id}) for {share_type} '{who}', was valid until {until}").format(
                secret=share.secret,
                secret_id=share.secret.hashid,
                share_type=_("user") if share.user else _("group"),
                until=share.granted_until,
                who=share.user or share.group,
            ),
        )
        share.delete()


@periodic_task(crontab(**settings.HUEY_TASKS['scheduler_frequency']))
def revoke_unused_shares():
    if settings.HUEY_TASKS['revoke_unused_shares_after_days'] is None:
        return

    grace_period = now() - timedelta(days=settings.HUEY_TASKS['revoke_unused_shares_after_days'])

    for share in SharedSecretData.objects.filter(
        granted_on__lt=grace_period,
    ):
        users_to_check = []

        if share.user:
            users_to_check.append(share.user)
        else:
            users_to_check.extend(share.group.user_set.all())

        do_revoke = True
        for user in users_to_check:
            accessed = LogEntry.objects.filter(
                actor=user,
                secret=share.secret,
                time__gte=grace_period,
            )
            if accessed:
                do_revoke = False
                # Skip further unnecessary checks.
                break

        if do_revoke:
            log(
                _(
                    "Share for {share_type} '{who}' automatically revoked, "
                    "not used since {grace_period}"
                ).format(
                    grace_period=grace_period,
                    share_type=_("user") if share.user else _("group"),
                    who=share.user or share.group,
                ),
                category=AuditLogCategoryChoices.SHARE_AUTOMATICALLY_REVOKED,
                level='info',
                secret=share.secret,
            )
            share.delete()
