# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='filename',
            field=models.CharField(blank=True, max_length=255, null=True),
            preserve_default=True,
        ),
    ]
