from urllib.parse import quote

from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import get_object_or_404
from django.views.generic import ListView

from ..secrets.models import Secret
from .models import LogEntry


class LogEntryList(ListView):
    context_object_name = 'log_entries'
    paginate_by = 100
    template_name = "audit/log.html"

    def get_context_data(self, **kwargs):
        context = super(LogEntryList, self).get_context_data(**kwargs)
        if "secret" in self.request.GET:
            context['secret'] = get_object_or_404(Secret, hashid=self.request.GET['secret'])
        else:
            context['secret'] = None
        context['audit_search_term'] = self.request.GET.get('search', None)
        context['audit_search_term_url'] = quote(self.request.GET.get('search', ""))
        return context

    def get_queryset(self):
        if "secret" in self.request.GET:
            secret = get_object_or_404(Secret, hashid=self.request.GET['secret'])
            return LogEntry.objects.filter(secret=secret)
        elif "search" in self.request.GET:
            raise NotImplementedError
        else:
            return LogEntry.objects.all()
auditlog = user_passes_test(lambda u: u.is_superuser)(LogEntryList.as_view())
