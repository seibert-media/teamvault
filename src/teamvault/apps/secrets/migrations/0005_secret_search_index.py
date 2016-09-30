# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0004_unaccent_extension'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='search_index',
            field=models.CharField(default="X", max_length=1),
            preserve_default=False,
        ),
    ]
