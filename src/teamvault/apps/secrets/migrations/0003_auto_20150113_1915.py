# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0002_secret_filename'),
    ]

    operations = [
        migrations.AddField(
            model_name='secretrevision',
            name='encrypted_data_sha256',
            field=models.CharField(default="0000000000000000000000000000000000000000000000000000000000000000", max_length=64),
            preserve_default=False,
        ),
        migrations.AlterUniqueTogether(
            name='secretrevision',
            unique_together=set([('encrypted_data_sha256', 'secret')]),
        ),
    ]
