# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0007_auto_20150205_1918'),
    ]

    operations = [
        migrations.AddField(
            model_name='accessrequest',
            name='hashid',
            field=models.CharField(unique=True, max_length=24, null=True),
        ),
        migrations.AddField(
            model_name='secret',
            name='hashid',
            field=models.CharField(unique=True, max_length=24, null=True),
        ),
        migrations.AddField(
            model_name='secretrevision',
            name='hashid',
            field=models.CharField(unique=True, max_length=24, null=True),
        ),
    ]
