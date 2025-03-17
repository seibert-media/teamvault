import enum

import django_filters
from django.contrib.auth import get_user_model
from django import forms
from django.db.models import IntegerChoices
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from teamvault.apps.secrets.models import Secret

User = get_user_model()


def add_tooltip(label, tooltip_message):
    return format_html(
        '{} '
        '<i class="fa fa-exclamation-circle fa-fw opacity-75"'
        ' data-bs-toggle="tooltip" data-bs-placement="top" title="{}">'
        '</i>',
        label,
        tooltip_message
    )


class Icons(enum.Enum):
    CREDIT_CARD = "fa-credit-card text-secondary"
    DELETED_DANGER = "fa-trash text-danger"
    FILE = "fa-file text-secondary"
    KEY = "fa-key text-secondary"
    REFRESH_DANGER = "fa-refresh text-danger"

    @property
    def html(self):
        return f'<i class="fa fa-fw {self.value}"></i> '


class ContentTypeChoice(IntegerChoices):
    # TODO: Merge CONTENT_* vars with these ones.
    #  Preferably migrate occurances of Secret.CONTENT_CHOICES to this class
    PASSWORD = Secret.CONTENT_PASSWORD, mark_safe(Icons.KEY.html + _('Password'))
    CREDIT_CARD = Secret.CONTENT_CC, mark_safe(Icons.CREDIT_CARD.html + _('Credit Card'))
    FILE = Secret.CONTENT_FILE, mark_safe(Icons.FILE.html + _('File'))


class StatusChoices(IntegerChoices):
    # TODO: Merge STATUS_* vars with these ones.
    #  Preferably migrate occurances of Secret.STATUS_CHOICES to this class
    OK = Secret.STATUS_OK, mark_safe(Icons.KEY.html + _('Regular'))
    NEEDS_CHANGING = Secret.STATUS_NEEDS_CHANGING, mark_safe(Icons.REFRESH_DANGER.html + _('Needs Changing'))
    DELETED = Secret.STATUS_DELETED, mark_safe(Icons.DELETED_DANGER.html) + f"{add_tooltip( _('Deleted'),_('Hide deleted secrets per default by changing your settings.'))}"


class SecretFilter(django_filters.FilterSet):
    content_type = django_filters.MultipleChoiceFilter(
        choices=ContentTypeChoice,
        widget=forms.CheckboxSelectMultiple,
        label=_('Type')
    )
    status = django_filters.MultipleChoiceFilter(
        choices=StatusChoices,
        widget=forms.CheckboxSelectMultiple,
        label=_('Status')
    )
    created_by = django_filters.ModelChoiceFilter(
        queryset=User.objects.all().order_by('username'),
    )

    class Meta:
        model = Secret
        fields = ['content_type', 'status', 'created_by']
