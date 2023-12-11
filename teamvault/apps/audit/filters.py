import django_filters
from django import forms
from django.contrib.auth.models import User
from django.utils.translation import gettext_lazy as _

from .models import LogEntry, AuditLogCategoryChoices
from ..secrets.models import Secret


class AuditLogFilter(django_filters.FilterSet):
    actor = django_filters.ModelChoiceFilter(
        to_field_name='username',
        queryset=User.objects.all().order_by('username'),
    )
    category = django_filters.MultipleChoiceFilter(
        choices=AuditLogCategoryChoices.choices,
        label=_('Categories'),
        widget=forms.CheckboxSelectMultiple(),
    )
    secret = django_filters.ModelChoiceFilter(
        field_name='secret',
        to_field_name='hashid',
        queryset=Secret.objects.all(),
    )
    user = django_filters.ModelChoiceFilter(
        to_field_name='username',
        queryset=User.objects.all().order_by('username'),
    )

    class Meta:
        model = LogEntry
        fields = ['secret', 'actor', 'user']
