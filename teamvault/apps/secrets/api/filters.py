import django_filters
from django_filters import rest_framework as filters

from teamvault.apps.secrets.api.serializers import (
    REPR_ACCESS_POLICY,
    REPR_CONTENT_TYPE,
    SECRET_REPR_STATUS,
)
from teamvault.apps.secrets.enums import SecretStatus
from teamvault.apps.secrets.models import Secret

# Deleted secrets are never returned by the list queryset, so they are not an
# allowed filter value.
SELECTABLE_STATUS = {repr_: value for repr_, value in SECRET_REPR_STATUS.items() if value != SecretStatus.DELETED}


def _string_choice_filter(repr_to_value):
    """ChoiceFilter accepting the API's string reprs (e.g. ``needs_changing``)
    and coercing them to the underlying integer field value.

    Invariant: ``choices`` and the coercion are both derived from
    ``repr_to_value``, so every value that passes choice-validation is
    guaranteed to be a key here. Callers MUST pass a single dict whose keys
    are exactly the valid API reprs — do not supply choices and coercion
    from different sources, or coercion can KeyError → HTTP 500.
    """
    return django_filters.TypedChoiceFilter(
        choices=[(repr_, repr_) for repr_ in repr_to_value],
        coerce=lambda value: repr_to_value[value],
    )


class SecretListFilter(filters.FilterSet):
    access_policy = _string_choice_filter(REPR_ACCESS_POLICY)
    content_type = _string_choice_filter(REPR_CONTENT_TYPE)
    status = _string_choice_filter(SELECTABLE_STATUS)

    name = django_filters.CharFilter(lookup_expr='icontains')
    url = django_filters.CharFilter(lookup_expr='icontains')
    username = django_filters.CharFilter(lookup_expr='icontains')
    created_by = django_filters.CharFilter(
        field_name='created_by__username',
        lookup_expr='icontains',
    )

    ordering = django_filters.OrderingFilter(
        fields=(
            ('last_read', 'last_read'),
            ('last_changed', 'last_changed'),
            ('created', 'created'),
            ('name', 'name'),
        ),
    )

    @property
    def qs(self):
        parent = super().qs
        # Guarantee a deterministic total order so LIMIT/OFFSET pagination
        # is stable across requests even when the sort key has ties.
        return parent.order_by(*parent.query.order_by, 'pk')

    class Meta:
        model = Secret
        fields = ('needs_changing_on_leave',)
