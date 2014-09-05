# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from json import dumps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponse, Http404
from django.views.generic import DetailView, ListView
from django.views.generic.edit import FormView

from .forms import AddPasswordForm #, AddCCForm, UploadFileForm
from .models import Password


_CONTENT_TYPES = dict(Password.CONTENT_CHOICES)
PRETTY_CONTENT_TYPES = {
    'cc': _CONTENT_TYPES[Password.CONTENT_CC],
    'file': _CONTENT_TYPES[Password.CONTENT_FILE],
    'password': _CONTENT_TYPES[Password.CONTENT_PASSWORD],
}


class PasswordAdd(FormView):
    template_name = 'secrets/add.html'
    form_class = AddPasswordForm

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.
        return super(PasswordAdd, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(PasswordAdd, self).get_context_data(**kwargs)
        context['content_type'] = self.kwargs['content_type']
        try:
            context['pretty_content_type'] = PRETTY_CONTENT_TYPES[self.kwargs['content_type']]
        except KeyError:
            raise Http404
        return context


class PasswordDetail(DetailView):
    context_object_name = 'password'
    model = Password
    template_name = "secrets/password.html"

    def get_context_data(self, **kwargs):
        context = super(PasswordDetail, self).get_context_data(**kwargs)
        password = self.get_object()
        context['readable'] = password.is_readable_by_user(self.request.user)
        context['secret_url'] = reverse(
            'api.password-revision_secret',
            kwargs={'pk': password.current_revision.pk},
        )
        if context['readable']:
            context['placeholder'] = password.current_revision.length * "•"
        else:
            context['placeholder'] = "<access denied>"
        return context

    def get_object(self):
        object = super(PasswordDetail, self).get_object()
        if not object.is_visible_to_user(self.request.user):
            raise PermissionDenied()
        return object


class PasswordList(ListView):
    context_object_name = 'passwords'
    template_name = "secrets/passwords.html"

    def get_context_data(self, **kwargs):
        context = super(PasswordList, self).get_context_data(**kwargs)
        context['readable_passwords'] = Password.get_all_readable_by_user(self.request.user)
        context['search_term'] = self.request.GET.get('search', None)
        return context

    def get_queryset(self):
        if "search" in self.request.GET:
            return Password.get_search_results(self.request.user, self.request.GET['search'])
        else:
            return Password.get_all_visible_to_user(self.request.user)


@login_required
def live_search(request):
    search_term = request.GET['q']
    search_result = []
    all_passwords = Password.get_all_visible_to_user(request.user)
    filtered_passwords = list(all_passwords.filter(name__icontains=search_term)[:20])
    unreadable_passwords = filtered_passwords[:]
    sorted_passwords = []

    # sort readable passwords to top...
    for password in filtered_passwords:
        if password.is_readable_by_user(request.user):
            sorted_passwords.append((password, "unlock"))
            unreadable_passwords.remove(password)

    # and others to the bottom
    for password in unreadable_passwords:
        sorted_passwords.append((password, "lock"))

    for password, icon in sorted_passwords:
        search_result.append({
            'name': password.name,
            'url': reverse('secrets.password-detail', kwargs={'pk': password.pk}),
            'icon': icon,
        })

    return HttpResponse(dumps(search_result), content_type="application/json")

