# Generated by Django 4.2.16 on 2024-11-14 13:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("audit", "0007_alter_logentry_category"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["category"], name="logentry_category_idx"),
        ),
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["time"], name="logentry_time_idx"),
        ),
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["category", "time"], name="logentry_category_time_idx"),
        ),
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["actor"], name="logentry_actor_idx"),
        ),
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["group"], name="logentry_group_idx"),
        ),
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["secret"], name="logentry_secret_idx"),
        ),
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["user"], name="logentry_user_idx"),
        ),
    ]