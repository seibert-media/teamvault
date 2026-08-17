from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0010_groupuuidmapping'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='entry_uuid',
            new_name='ldap_uuid',
        ),
        migrations.RenameField(
            model_name='groupuuidmapping',
            old_name='entry_uuid',
            new_name='ldap_uuid',
        ),
    ]
