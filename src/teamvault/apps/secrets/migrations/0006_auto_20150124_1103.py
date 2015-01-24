# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0005_secret_search_index'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='secret',
            options={'ordering': ('name', 'username')},
        ),
    ]
