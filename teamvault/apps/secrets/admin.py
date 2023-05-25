from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from .models import Secret, SecretRevision


class SecretAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': (
                'name',
                'content_type',
                'description',
            ),
        }),
        (_("Audit"), {
            'fields': (
                'created',
                'last_read',
            ),
        }),
        (_("Security"), {
            'fields': (
                'status',
                'access_policy',
                'needs_changing_on_leave',
                'allowed_groups',
                'allowed_users',
            ),
        }),
    )
    date_hierarchy = 'created'
    list_display = ('name', 'last_read')
    list_filter = ('access_policy', 'needs_changing_on_leave', 'status')
    radio_fields = {
        'access_policy': admin.HORIZONTAL,
        'status': admin.HORIZONTAL,
    }
    readonly_fields = ('created', 'last_read')
    search_fields = ('name', 'description')

admin.site.register(Secret, SecretAdmin)


class SecretRevisionAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': (
                'secret',
                'encrypted_data',
            ),
        }),
        (_("Audit"), {
            'fields': (
                'created',
                'set_by',
                'accessed_by',
            ),
        }),
    )
    date_hierarchy = 'created'
    list_display = ('secret', 'id', 'created')
    readonly_fields = ('accessed_by', 'created', 'set_by')
    search_fields = ('secret__name',)

admin.site.register(SecretRevision, SecretRevisionAdmin)
