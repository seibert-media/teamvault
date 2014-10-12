# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from json import dumps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.views.generic import DetailView, ListView
from django.views.generic.edit import FormView

from .forms import AddCCForm, AddFileForm, AddPasswordForm
from .models import Secret

CONTENT_TYPE_FORMS = {
    'cc': AddCCForm,
    'file': AddFileForm,
    'password': AddPasswordForm,
}
CONTENT_TYPE_IDS = {
    'cc': Secret.CONTENT_CC,
    'file': Secret.CONTENT_FILE,
    'password': Secret.CONTENT_PASSWORD,
}
_CONTENT_TYPES = dict(Secret.CONTENT_CHOICES)
CONTENT_TYPE_NAMES = {
    'cc': _CONTENT_TYPES[Secret.CONTENT_CC],
    'file': _CONTENT_TYPES[Secret.CONTENT_FILE],
    'password': _CONTENT_TYPES[Secret.CONTENT_PASSWORD],
}


class SecretAdd(FormView):
    def form_valid(self, form):
        secret = Secret()
        secret.content_type = CONTENT_TYPE_IDS[self.kwargs['content_type']]
        secret.created_by = self.request.user
        for attr in ('access_policy', 'description', 'name', 'needs_changing_on_leave', 'url',
                     'username'):
            setattr(secret, attr, form.cleaned_data[attr])
        secret.save()
        if secret.content_type == Secret.CONTENT_PASSWORD:
            plaintext_data = form.cleaned_data['password']
        secret.set_data(self.request.user, plaintext_data)
        return HttpResponseRedirect(secret.get_absolute_url())

    def get_context_data(self, **kwargs):
        context = super(SecretAdd, self).get_context_data(**kwargs)
        context['content_type'] = self.kwargs['content_type']
        try:
            context['pretty_content_type'] = CONTENT_TYPE_NAMES[self.kwargs['content_type']]
        except KeyError:
            raise Http404
        return context

    def get_form_class(self):
        return CONTENT_TYPE_FORMS[self.kwargs['content_type']]

    def get_template_names(self):
        return "secrets/addedit_{}.html".format(self.kwargs['content_type'])


@login_required
def secret_delete(request, pk):
    secret = get_object_or_404(Secret, pk=pk)
    if not secret.is_visible_to_user(request.user):
        raise Http404
    if not secret.is_readable_by_user(request.user):
        raise PermissionDenied()
    if request.method == 'POST':
        log(_(
                "{user} deleted '{name}' ({id}:{revision})"
            ).format(
                id=secret.id,
                name=secret.name,
                revision=secret.current_revision.id,
                user=request.user.username,
            ),
            actor=request.user,
            level='info',
            secret=secret,
            secret_revision=secret.current_revision,
        )
        secret.status = Secret.STATUS_DELETED
        secret.save()
        return HttpResponseRedirect(reverse('secrets.secret-list') + "?" + urlencode([("search", secret.name.encode('utf-8'))]))
    else:
        return render(request, "secrets/delete.html", {'secret': secret})


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

