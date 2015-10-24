# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import djorm_pgfulltext.fields


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0009_auto_20150322_0949'),
    ]

    operations = [
        migrations.AlterField(
            model_name='secret',
            name='search_index',
            field=djorm_pgfulltext.fields.VectorField(),
        ),
    ]
