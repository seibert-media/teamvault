import django_filters
from django.contrib.auth import get_user_model
from django import forms
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from teamvault.apps.secrets.enums import ContentType, SecretStatus
from teamvault.apps.secrets.models import Secret

User = get_user_model()


def add_tooltip(label, tooltip_message):
    return format_html(
        "{} "
        '<i class="fa fa-exclamation-circle fa-fw opacity-75"'
        ' data-bs-toggle="tooltip" data-bs-placement="top" title="{}">'
        "</i>",
        label,
        tooltip_message,
    )


ICON_MAP = {
    ContentType.PASSWORD: "fa-key text-secondary",
    ContentType.CC: "fa-credit-card text-secondary",
    ContentType.FILE: "fa-file text-secondary",
}


def icon_html(choice):
    return mark_safe(f'<i class="fa fa-fw {ICON_MAP[choice]}"></i>')


STATUS_ICON = {
    SecretStatus.OK: "fa-key text-secondary",
    SecretStatus.NEEDS_CHANGING: "fa-refresh text-danger",
    SecretStatus.DELETED: "fa-trash text-danger",
}


def status_label(choice):
    base = mark_safe(f'<i class="fa fa-fw {STATUS_ICON[choice]}"></i>')
    if choice is SecretStatus.DELETED:
        tooltip = add_tooltip(
            _("Deleted"),
            _("Hide deleted secrets per default by changing your settings."),
        )
        return mark_safe(base + tooltip)
    return base + choice.label


class SecretFilter(django_filters.FilterSet):
    content_type = django_filters.MultipleChoiceFilter(
        choices=[(c.value, mark_safe(icon_html(c) + c.label)) for c in ContentType],
        widget=forms.CheckboxSelectMultiple,
        label=_("Type"),
    )
    status = django_filters.MultipleChoiceFilter(
        choices=[(s.value, status_label(s)) for s in SecretStatus],
        widget=forms.CheckboxSelectMultiple,
        label=_("Status"),
    )
    created_by = django_filters.ModelChoiceFilter(
        queryset=User.objects.all().order_by("username"),
    )

    class Meta:
        model = Secret
        fields = ["content_type", "status", "created_by"]
