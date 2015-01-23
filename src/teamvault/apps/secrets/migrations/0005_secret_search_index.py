# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import djorm_pgfulltext.fields


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0004_unaccent_extension'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='search_index',
            field=djorm_pgfulltext.fields.VectorField(null=True, db_index=True, default='', editable=False, serialize=False),
        ),
    ]
