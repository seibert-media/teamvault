from django.db import models
from django.utils.translation import gettext_lazy as _


class Setting(models.Model):
    key = models.CharField(
        max_length=64,
        unique=True,
    )
    value = models.CharField(
        max_length=255,
    )

    class Meta:
        ordering = ('key',)

    @classmethod
    def get(cls, key, **kwargs):
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            try:
                return kwargs['default']
            except KeyError:
                raise KeyError(_("value for '{}' not set").format(key))

    @classmethod
    def set(cls, key, value):
        try:
            setting = cls.objects.get(key=key)
        except cls.DoesNotExist:
            setting = cls()
            setting.key = key
        setting.value = value
        setting.save()
