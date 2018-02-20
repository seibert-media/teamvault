# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('auth', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AccessRequest',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True, serialize=False)),
                ('closed', models.DateTimeField(null=True, blank=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('reason_request', models.TextField(null=True, blank=True)),
                ('reason_rejected', models.TextField(null=True, blank=True)),
                ('status', models.PositiveSmallIntegerField(default=1, choices=[(1, 'pending'), (2, 'rejected'), (3, 'approved')])),
                ('closed_by', models.ForeignKey(null=True, blank=True, on_delete=models.CASCADE, related_name='access_requests_closed', to=settings.AUTH_USER_MODEL)),
                ('requester', models.ForeignKey(on_delete=models.CASCADE, to=settings.AUTH_USER_MODEL, related_name='access_requests_created')),
                ('reviewers', models.ManyToManyField(to=settings.AUTH_USER_MODEL, related_name='access_requests_reviewed')),
            ],
            options={
                'ordering': ('-created',),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Secret',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True, serialize=False)),
                ('access_policy', models.PositiveSmallIntegerField(default=1, choices=[(1, 'request'), (2, 'everyone'), (3, 'hidden')])),
                ('content_type', models.PositiveSmallIntegerField(default=1, choices=[(1, 'Password'), (2, 'Credit Card'), (3, 'File')])),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('description', models.TextField(null=True, blank=True)),
                ('last_read', models.DateTimeField(default=django.utils.timezone.now)),
                ('name', models.CharField(max_length=92)),
                ('needs_changing_on_leave', models.BooleanField(default=True)),
                ('status', models.PositiveSmallIntegerField(default=1, choices=[(1, 'OK'), (2, 'needs changing'), (3, 'deleted')])),
                ('url', models.URLField(null=True, blank=True)),
                ('username', models.CharField(null=True, max_length=255, blank=True)),
                ('allowed_groups', models.ManyToManyField(to='auth.Group', blank=True, related_name='allowed_passwords')),
                ('allowed_users', models.ManyToManyField(to=settings.AUTH_USER_MODEL, blank=True, related_name='allowed_passwords')),
                ('created_by', models.ForeignKey(on_delete=models.CASCADE, to=settings.AUTH_USER_MODEL, related_name='passwords_created')),
            ],
            options={
                'ordering': ('name',),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='SecretRevision',
            fields=[
                ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('encrypted_data', models.BinaryField()),
                ('length', models.PositiveIntegerField(default=0)),
                ('accessed_by', models.ManyToManyField(to=settings.AUTH_USER_MODEL)),
                ('secret', models.ForeignKey(on_delete=models.CASCADE, to='secrets.Secret')),
                ('set_by', models.ForeignKey(on_delete=models.CASCADE, to=settings.AUTH_USER_MODEL, related_name='password_revisions_set')),
            ],
            options={
                'ordering': ('-created',),
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='secretrevision',
            unique_together=set([('encrypted_data', 'secret')]),
        ),
        migrations.AddField(
            model_name='secret',
            name='current_revision',
            field=models.ForeignKey(null=True, blank=True, on_delete=models.CASCADE, related_name='_password_current_revision', to='secrets.SecretRevision'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='accessrequest',
            name='secret',
            field=models.ForeignKey(on_delete=models.CASCADE, to='secrets.Secret', related_name='access_requests'),
            preserve_default=True,
        ),
    ]
