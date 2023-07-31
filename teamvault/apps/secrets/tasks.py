import logging

from huey import crontab
from huey.contrib.djhuey import db_periodic_task

from teamvault.apps.secrets.revoke_access import revoke_unused_access

huey_log = logging.getLogger('huey')


@db_periodic_task(crontab(minute='*/1'))
def add(a=1, b=5):
    huey_log.info(f'Whoah {a} + {b} is {a + b}')
    return a + b


@db_periodic_task(crontab(minute=0, hour=0))
def periodic_revoke_unused_access():
    revoke_unused_access()
