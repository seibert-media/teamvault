# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import teamvault.apps.secrets.models


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0006_auto_20150124_1103'),
    ]

    operations = [
        migrations.AlterField(
            model_name='secret',
            name='url',
            field=models.CharField(blank=True, null=True, validators=[teamvault.apps.secrets.models.validate_url], max_length=255),
        ),
    ]
