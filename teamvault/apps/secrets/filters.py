import django_filters

from teamvault.apps.secrets.models import Secret


class SecretFilter(django_filters.FilterSet):
    """
    order = django_filters.OrderingFilter(
        choices=(
            ('last_changed', _("Last changed")),
            ('last_read', _("Last read")),
        ),
    )
    """
    content_type = django_filters.MultipleChoiceFilter(choices=Secret.CONTENT_CHOICES)
    status = django_filters.MultipleChoiceFilter(choices=Secret.STATUS_CHOICES)

    class Meta:
        model = Secret
        fields = ['content_type', 'status']
        """
        fields = {
            # 'last_changed': ['gt', 'gte', 'lt', 'lte'],
            # 'last_read': ['gt', 'gte', 'lt', 'lte'],
            # 'content_type': ['in']
        }
        """
