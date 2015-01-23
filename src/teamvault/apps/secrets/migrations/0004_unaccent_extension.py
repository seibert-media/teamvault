# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib.postgres.operations import UnaccentExtension
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('secrets', '0003_auto_20150113_1915'),
    ]
    operations = [
        UnaccentExtension(),
    ]
