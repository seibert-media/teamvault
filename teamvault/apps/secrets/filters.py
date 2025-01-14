import django_filters
from django.contrib.auth import get_user_model

from teamvault.apps.secrets.models import Secret

User = get_user_model()


class SecretFilter(django_filters.FilterSet):
    content_type = django_filters.MultipleChoiceFilter(choices=Secret.CONTENT_CHOICES)
    status = django_filters.MultipleChoiceFilter(choices=Secret.STATUS_CHOICES)
    created_by = django_filters.ModelChoiceFilter(
        queryset=User.objects.all(),
        label='Created By'
    )

    class Meta:
        model = Secret
        fields = ['content_type', 'status', 'created_by']
