# Generated by Django 2.2.4 on 2019-08-22 12:34

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0021_auto_20180220_1428'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='last_changed',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]
