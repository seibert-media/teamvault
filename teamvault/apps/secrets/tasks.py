import logging

from ..secrets.models import SharedSecretData

from django.utils.translation import gettext_lazy as _
from huey import crontab
from huey.contrib.djhuey import periodic_task


huey_log = logging.getLogger('huey')


@periodic_task(crontab(minute='*/1'))
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
