from json import dumps

from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User, Group
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView


@login_required
def search_groups(request):
    search_term = request.GET['q']
    search_result = {'results': []}
    groups = Group.objects.filter(name__icontains=search_term)
    for group in groups:
        search_result['results'].append({'id': group.id, 'text': group.name})
    return HttpResponse(dumps(search_result), content_type="application/json")


@login_required
def search_users(request):
    search_term = request.GET['q']
    search_result = {'results': []}
    users = User.objects.filter(
        is_active=True,
        username__icontains=search_term,
    )
    for user in users:
        search_result['results'].append({'id': user.id, 'text': user.username})
    return HttpResponse(dumps(search_result), content_type="application/json")


class UserList(ListView):
    context_object_name = 'users'
    paginate_by = 100
    template_name = "accounts/user_list.html"

    def get_queryset(self):
        return User.objects.order_by('username')
users = user_passes_test(lambda u: u.is_superuser)(UserList.as_view())


class UserDetail(DetailView):
    context_object_name = 'user'
    template_name = "accounts/user_detail.html"

    def get_object(self):
        return get_object_or_404(
            User,
            id=self.kwargs['uid'],
        )
user_detail = user_passes_test(lambda u: u.is_superuser)(UserDetail.as_view())
