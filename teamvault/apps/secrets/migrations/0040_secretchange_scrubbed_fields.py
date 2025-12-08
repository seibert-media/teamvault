from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secrets', '0039_migrate_old_file_saves_into_new_format'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='secretchange',
            name='scrubbed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='secretchange',
            name='scrubbed_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.SET_NULL,
                related_name='scrubbed_secret_changes',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
