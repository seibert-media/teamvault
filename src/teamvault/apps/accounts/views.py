from json import dumps

from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User, Group
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView

from ..audit.auditlog import log
from ..secrets.models import Secret, SecretRevision


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


@user_passes_test(lambda u: u.is_superuser)
@require_http_methods(["POST"])
def user_activate(request, uid, deactivate=False):
    user = get_object_or_404(
        User,
        id=uid,
        is_active=deactivate,
    )
    user.is_active = not deactivate
    user.save()
    if deactivate:
        accessed_revs = SecretRevision.objects.filter(
            accessed_by=user,
        ).exclude(
            secret__status=Secret.STATUS_NEEDS_CHANGING,
        ).select_related(
            'secret',
        )
        secrets = set()
        for rev in accessed_revs:
            if rev.is_current_revision:
                secrets.add(rev.secret)
        with transaction.atomic():
            for secret in secrets:
                secret.status = Secret.STATUS_NEEDS_CHANGING
                secret.save()
        log(
            _("{actor} deactivated {user}, {secrets} secrets marked for changing").format(
                actor=request.user.username,
                user=user.username,
                secrets=len(secrets),
            ),
            actor=request.user,
            user=user,
        )
    else:
        log(
            _("{actor} reactivated {user}").format(
                actor=request.user.username,
                user=user.username,
            ),
            actor=request.user,
            user=user,
        )
    return HttpResponseRedirect(reverse('accounts.user-detail', kwargs={'uid': user.id}))
