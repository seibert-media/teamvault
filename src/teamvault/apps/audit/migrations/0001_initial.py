# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('auth', '0005_alter_user_last_login_null'),
        ('secrets', '0006_auto_20150124_1103'),
    ]

    operations = [
        migrations.CreateModel(
            name='LogEntry',
            fields=[
                ('id', models.AutoField(serialize=False, verbose_name='ID', primary_key=True, auto_created=True)),
                ('message', models.TextField()),
                ('time', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(null=True, on_delete=models.CASCADE, related_name='logged_actions', to=settings.AUTH_USER_MODEL, blank=True)),
                ('group', models.ForeignKey(null=True, on_delete=models.CASCADE, related_name='logged_actions', to='auth.Group', blank=True)),
                ('secret', models.ForeignKey(null=True, on_delete=models.CASCADE, related_name='logged_actions', to='secrets.Secret', blank=True)),
                ('secret_revision', models.ForeignKey(null=True, on_delete=models.CASCADE, related_name='logged_actions', to='secrets.SecretRevision', blank=True)),
                ('user', models.ForeignKey(null=True, on_delete=models.CASCADE, related_name='affected_by_actions', to=settings.AUTH_USER_MODEL, blank=True)),
            ],
            options={
                'ordering': ('-time',),
            },
        ),
    ]
