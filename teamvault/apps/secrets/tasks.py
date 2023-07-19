import logging

from huey import crontab
from huey.contrib.djhuey import db_periodic_task

huey_log = logging.getLogger('huey')


@db_periodic_task(crontab(minute='*/1'))
def add(a=1, b=5):
    huey_log.info(f'Whoah {a} + {b} is {a + b}')
    return a + b
