from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test, login_required
from django.contrib.auth.models import User
from django.db import transaction
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView, UpdateView

from .forms import UserProfileForm
from .models import UserProfile as UserProfileModel
from ..audit.auditlog import log
from ..audit.models import AuditLogCategoryChoices
from ..secrets.models import Secret, SecretRevision


class UserProfile(UpdateView):
    form_class = UserProfileForm
    model = UserProfileModel
    template_name = "accounts/user_settings.html"
    success_url = reverse_lazy('accounts.user-settings')

    def get_object(self, *args, **kwargs):
        return UserProfileModel.objects.get_or_create(user=self.request.user)[0]

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, _('Successfully updated settings.'))
        return response


user_settings = login_required(UserProfile.as_view())


class UserList(ListView):
    context_object_name = 'users'
    paginate_by = 25
    template_name = "accounts/user_list.html"

    def get_queryset(self):
        return User.objects.order_by('username')


users = user_passes_test(lambda u: u.is_superuser)(UserList.as_view())


class UserDetail(DetailView):
    context_object_name = 'user'
    model = User
    slug_field = 'username'
    slug_url_kwarg = 'username'
    template_name = 'accounts/user_detail.html'


user_detail = user_passes_test(lambda u: u.is_superuser)(UserDetail.as_view())


@user_passes_test(lambda u: u.is_superuser)
@require_http_methods(["POST"])
def user_activate(request, username, deactivate=False):
    user = get_object_or_404(
        User,
        username=username,
        is_active=deactivate,
    )
    user.is_active = not deactivate
    user.save()
    if deactivate:
        user.groups.clear()
        accessed_revs = SecretRevision.objects.filter(
            accessed_by=user,
        ).exclude(
            secret__needs_changing_on_leave=False,
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
                msg = _(
                    "secret '{secret}' needs changing because user '{user}' was deactivated"
                ).format(
                    secret=secret.name,
                    user=user.username,
                )
                log(
                    msg,
                    actor=request.user,
                    category=AuditLogCategoryChoices.USER_DEACTIVATED,
                    secret=secret,
                    user=user,
                )
        log(
            _("{actor} deactivated {user}, {secrets} secrets marked for changing").format(
                actor=request.user.username,
                user=user.username,
                secrets=len(secrets),
            ),
            actor=request.user,
            category=AuditLogCategoryChoices.USER_DEACTIVATED,
            user=user,
        )
    else:
        log(
            _("{actor} reactivated {user}").format(
                actor=request.user.username,
                user=user.username,
            ),
            actor=request.user,
            category=AuditLogCategoryChoices.USER_ACTIVATED,
            user=user,
        )
    return HttpResponseRedirect(reverse('accounts.user-detail', kwargs={'username': user.username}))
