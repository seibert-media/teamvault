from django.contrib import admin

from .models import Setting


class SettingAdmin(admin.ModelAdmin):
    fieldsets = (
        (None, {
            'fields': (
                'key',
                'value',
            ),
        }),
    )
    list_display = ('key', 'value')
    search_fields = ('key',)

admin.site.register(Setting, SettingAdmin)
