from django.contrib import admin
from django.utils.translation import ugettext_lazy as _

from .models import LogEntry


class LogEntryAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': (
                'time',
                'message',
            ),
        }),
        (_("Linked objects"), {
            'fields': (
                'actor',
                'secret',
                'secret_revision',
                'group',
                'user',
            ),
        }),
    )
    date_hierarchy = 'time'
    list_display = ('time', 'message')
    readonly_fields = (
        'time',
        'message',
        'actor',
        'secret',
        'secret_revision',
        'group',
        'user',
    )
    search_fields = ('message', 'actor__username')

admin.site.register(LogEntry, LogEntryAdmin)
