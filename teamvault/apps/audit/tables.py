import django_tables2 as tables
from django_tables2 import A

from .models import LogEntry


class LogEntryTable(tables.Table):
    secret = tables.LinkColumn('secrets.secret-detail', kwargs={'hashid': A('secret__hashid')})
    time = tables.DateTimeColumn(
        format='Y-m-d H:i:s e'
    )

    class Meta:
        model = LogEntry
        fields = ('time', 'actor', 'secret', 'message')
        order_by = '-time'
        template_name = "helpers/table.html"
