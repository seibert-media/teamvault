# Generated by Django 4.2.5 on 2024-02-13 15:00

from django.db import migrations, models


def categorize_log_entries_of_shares(apps, schema_editor):
    log_entry_model = apps.get_model('audit', 'LogEntry')
    log_entry_model.objects.filter(
        category='secret_shared',
        message__regex=r"^.* removed access of \w+ '.*'.*$",
    ).update(
        category='secret_share_removed'
    )


def categorize_log_entries_of_shares_reverse(apps, schema_editor):
    log_entry_model = apps.get_model('audit', 'LogEntry')
    log_entry_model.objects.filter(
        category='secret_share_removed'
    ).update(
        category='secret_shared'
    )


class Migration(migrations.Migration):
    dependencies = [
        ("audit", "0004_alter_logentry_category"),
    ]

    operations = [
        migrations.AlterField(
            model_name="logentry",
            name="category",
            field=models.CharField(
                choices=[
                    ("secret_read", "secret_read"),
                    ("secret_elevated_superuser_read", "secret_elevated_superuser_read"),
                    ("secret_permission_violation", "secret_permission_violation"),
                    ("secret_changed", "secret_changed"),
                    ("secret_needs_changing_reminder", "secret_needs_changing_reminder"),
                    ("secret_shared", "secret_shared"),
                    ("secret_superuser_shared", "secret_superuser_shared"),
                    ("secret_share_removed", "secret_share_removed"),
                    ("secret_superuser_share_removed", "secret_superuser_share_removed"),
                    ("secret_legacy_access_requests", "secret_legacy_access_requests"),
                    ("user_activated", "user_activated"),
                    ("user_deactivated", "user_deactivated"),
                    ("user_settings_changed", "user_settings_changed"),
                    ("miscellaneous", "miscellaneous"),
                ],
                default="miscellaneous",
                max_length=64,
            ),
        ),
        migrations.RunPython(
            code=categorize_log_entries_of_shares,
            reverse_code=categorize_log_entries_of_shares_reverse,
        ),
    ]
