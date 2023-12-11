import django_filters

from teamvault.apps.secrets.models import Secret


class SecretFilter(django_filters.FilterSet):
    content_type = django_filters.MultipleChoiceFilter(choices=Secret.CONTENT_CHOICES)
    status = django_filters.MultipleChoiceFilter(choices=Secret.STATUS_CHOICES)

    class Meta:
        model = Secret
        fields = ['content_type', 'status']
