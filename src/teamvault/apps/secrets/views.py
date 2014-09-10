# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from json import dumps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponse, Http404
from django.views.generic import DetailView, ListView
from django.views.generic.edit import FormView

from .forms import AddSecretForm #, AddCCForm, UploadFileForm
from .models import Secret


_CONTENT_TYPES = dict(Secret.CONTENT_CHOICES)
PRETTY_CONTENT_TYPES = {
    'cc': _CONTENT_TYPES[Secret.CONTENT_CC],
    'file': _CONTENT_TYPES[Secret.CONTENT_FILE],
    'password': _CONTENT_TYPES[Secret.CONTENT_PASSWORD],
}


class SecretAdd(FormView):
    template_name = 'secrets/add.html'
    form_class = AddSecretForm

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.
        return super(SecretAdd, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(SecretAdd, self).get_context_data(**kwargs)
        context['content_type'] = self.kwargs['content_type']
        try:
            context['pretty_content_type'] = PRETTY_CONTENT_TYPES[self.kwargs['content_type']]
        except KeyError:
            raise Http404
        return context


class SecretDetail(DetailView):
    context_object_name = 'secret'
    model = Secret
    template_name = "secrets/detail.html"

    def get_context_data(self, **kwargs):
        context = super(SecretDetail, self).get_context_data(**kwargs)
        secret = self.get_object()
        context['readable'] = secret.is_readable_by_user(self.request.user)
        context['secret_url'] = reverse(
            'api.secret-revision_secret',
            kwargs={'pk': secret.current_revision.pk},
        )
        if context['readable']:
            context['placeholder'] = secret.current_revision.length * "•"
        else:
            context['placeholder'] = "<access denied>"
        return context

    def get_object(self):
        object = super(SecretDetail, self).get_object()
        if not object.is_visible_to_user(self.request.user):
            raise PermissionDenied()
        return object


class SecretList(ListView):
    context_object_name = 'secrets'
    template_name = "secrets/list.html"

    def get_context_data(self, **kwargs):
        context = super(SecretList, self).get_context_data(**kwargs)
        context['readable_secrets'] = Secret.get_all_readable_by_user(self.request.user)
        context['search_term'] = self.request.GET.get('search', None)
        return context

    def get_queryset(self):
        if "search" in self.request.GET:
            return Secret.get_search_results(self.request.user, self.request.GET['search'])
        else:
            return Secret.get_all_visible_to_user(self.request.user)


@login_required
def live_search(request):
    search_term = request.GET['q']
    search_result = []
    all_secrets = Secret.get_all_visible_to_user(request.user)
    filtered_secrets = list(all_secrets.filter(name__icontains=search_term)[:20])
    unreadable_secrets = filtered_secrets[:]
    sorted_secrets = []

    # sort readable passwords to top...
    for secret in filtered_secrets:
        if secret.is_readable_by_user(request.user):
            sorted_secrets.append((secret, "unlock"))
            unreadable_secrets.remove(secret)

    # and others to the bottom
    for secret in unreadable_secrets:
        sorted_secrets.append((secret, "lock"))

    for secret, icon in sorted_secrets:
        search_result.append({
            'name': secret.name,
            'url': reverse('secrets.secret-detail', kwargs={'pk': secret.pk}),
            'icon': icon,
        })

    return HttpResponse(dumps(search_result), content_type="application/json")

