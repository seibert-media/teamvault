from django.contrib.auth.decorators import user_passes_test
from django.db.models import Q
from django.views.generic import ListView

from .filters import AuditLogFilter
from .models import LogEntry
from ..secrets.models import Secret
from ...views import FilterMixin


class LogEntryList(ListView, FilterMixin):
    filter = None
    filter_class = AuditLogFilter
    context_object_name = 'log_entries'
    paginate_by = 25
    template_name = "audit/log.html"

    def get_queryset(self):
        queryset = LogEntry.objects.all()
        if "search" in self.request.GET:
            query = self.request.GET['search']
            queryset = queryset.filter(
                Q(actor__icontains=query) |
                Q(message__icontains=query)
            )

        return self.get_filtered_queryset(queryset)

    @staticmethod
    def manipulate_filter_form(bound_data, filter_form):
        # Set queryset since we'll retrieve choices via ajax and need to show the initial one
        if bound_data.get('secret'):
            secret_choices = Secret.objects.filter(pk=bound_data['secret'].pk)
        else:
            secret_choices = Secret.objects.none()
        filter_form.fields['secret'].queryset = secret_choices
        return filter_form


auditlog = user_passes_test(lambda u: u.is_superuser)(LogEntryList.as_view())
