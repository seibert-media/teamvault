# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations


def generate_hashids(apps, schema_editor):
    AccessRequest = apps.get_model("secrets", "AccessRequest")
    Secret = apps.get_model("secrets", "Secret")
    SecretRevision = apps.get_model("secrets", "SecretRevision")

    for model_class in (AccessRequest, Secret, SecretRevision):
        for obj in model_class.objects.all():
            obj.save()


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0008_auto_20150322_0944'),
    ]

    operations = [
        migrations.RunPython(generate_hashids),
    ]
