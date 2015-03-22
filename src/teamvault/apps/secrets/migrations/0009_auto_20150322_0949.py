# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations
from hashids import Hashids


def generate_hashids(apps, schema_editor):
    AccessRequest = apps.get_model("secrets", "AccessRequest")
    Secret = apps.get_model("secrets", "Secret")
    SecretRevision = apps.get_model("secrets", "SecretRevision")

    for model_class, hashid_namespace in (
        (AccessRequest, "AccessRequest"),
        (Secret, "Secret"),
        (SecretRevision, "SecretRevision"),
    ):
        for obj in model_class.objects.all():
            if not obj.hashid:
                # We cannot use the same salt for every model because
                # 1. sequentially create lots of secrets
                # 2. note the hashid of each secrets
                # 3. you can now enumerate access requests by using the same
                #    hashids
                # it's not a huge deal, but let's avoid it anyway
                hasher = Hashids(
                    min_length=settings.HASHID_MIN_LENGTH,
                    salt=hashid_namespace + settings.HASHID_SALT,
                )
                obj.hashid = hasher.encode(obj.pk)
            obj.save()


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0008_auto_20150322_0944'),
    ]

    operations = [
        migrations.RunPython(generate_hashids),
    ]
