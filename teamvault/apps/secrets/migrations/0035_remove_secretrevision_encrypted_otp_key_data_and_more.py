# Generated by Django 4.2.13 on 2024-08-08 14:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0034_remove_secretrevision_encrypted_otp_key_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='secretrevision',
            name='encrypted_otp_key_data',
        ),
        migrations.AddField(
            model_name='secretrevision',
            name='otp_key_set',
            field=models.BooleanField(default=False),
        ),
    ]
