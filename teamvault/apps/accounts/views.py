import csv
from functools import cached_property

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Max, Q
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
    JsonResponse,
)
from django.shortcuts import get_object_or_404, render
from django.urls import reverse, reverse_lazy
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView, UpdateView

from teamvault.apps.secrets.enums import SecretStatus
from teamvault.views import PageSizeMixin
from .forms import UserProfileForm
from .models import UserProfile as UserProfileModel
from .utils import get_pending_secrets_for_user
from ..audit.auditlog import log
from ..audit.models import AuditLogCategoryChoices
from ..secrets.models import AccessPermissionTypes, Secret, SecretRevision


class UserProfile(UpdateView):
    form_class = UserProfileForm
    model = UserProfileModel
    template_name = 'accounts/user_settings.html'
    success_url = reverse_lazy('accounts.user-settings')

    def get_object(self, *args, **kwargs):  # noqa: ARG002
        return UserProfileModel.objects.get_or_create(user=self.request.user)[0]

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, _('Successfully updated settings.'))
        return response


user_settings = login_required(UserProfile.as_view())


class UserList(PageSizeMixin, ListView):
    context_object_name = 'users'
    model = User
    paginate_by = 25
    template_name = 'accounts/user_list.html'

    def get_queryset(self):
        return self.model.objects.order_by('username')


users = user_passes_test(lambda u: u.is_superuser)(UserList.as_view())


class UserDetail(DetailView):
    context_object_name = 'user'
    model = User
    slug_field = 'username'
    slug_url_kwarg = 'username'
    template_name = 'accounts/user_detail.html'

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        user_obj = self.object

        pending_qs = get_pending_secrets_for_user(user_obj)

        query = self.request.GET.get('q')
        if query:
            pending_qs = pending_qs.filter(name__icontains=query)

        page_size = self.request.GET.get('page_size', '10')
        if page_size not in {'10', '25', '50', '100'}:
            page_size = '10'
        page_size = int(page_size)

        paginator = Paginator(pending_qs, page_size)
        page_number = self.request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        for secret in page_obj:
            perm = secret.is_readable(self.request.user)
            secret.readable_for_admin = perm != AccessPermissionTypes.NOT_ALLOWED

        ctx['pending_secrets'] = page_obj
        ctx['page_obj'] = page_obj
        ctx['paginator'] = paginator
        ctx['is_paginated'] = page_obj.has_other_pages()
        ctx['show_pending_modal'] = self.request.GET.get('show_pending') == '1'
        ctx['current_page_size'] = page_size

        return ctx


user_detail = user_passes_test(lambda u: u.is_superuser)(UserDetail.as_view())


class UserPendingSecretsView(PageSizeMixin, ListView):
    paginate_by = 10
    context_object_name = 'pending_secrets'
    template_name = 'accounts/user_pending_secrets.html'

    @cached_property
    def user_object(self):
        return get_object_or_404(User, username=self.kwargs['username'])

    def get_queryset(self):
        qs = get_pending_secrets_for_user(self.user_object)
        query = self.request.GET.get('q')

        if query:
            qs = qs.filter(name__icontains=query)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        page_secrets = ctx['pending_secrets']
        secret_ids = [s.id for s in page_secrets]

        readable_secret_ids = set(
            Secret.get_all_readable_by_user(self.request.user).filter(id__in=secret_ids).values_list('id', flat=True)
        )

        for secret in page_secrets:
            secret.readable_for_admin = secret.id in readable_secret_ids

        ctx['is_htmx'] = self.request.headers.get('HX-Request') == 'true'
        ctx['deactivated_user'] = self.user_object
        ctx['user'] = self.user_object

        return ctx

    def get_template_names(self):
        if self.request.headers.get('HX-Request') == 'true':
            # If searching or paginating, returning only the table content
            if (
                self.request.GET.get('q') is not None
                or self.request.GET.get('page')
                or self.request.GET.get('page_size')
            ):
                return [f'{self.template_name}#user-pending-secrets-content']
            # Otherwise (initial load via HTMX), return the full container
            return [f'{self.template_name}#user-pending-secrets-container']

        return [self.template_name]


user_pending_secrets = user_passes_test(lambda u: u.is_superuser)(UserPendingSecretsView.as_view())


@user_passes_test(lambda u: u.is_superuser)
def user_detail_from_request(request):
    username = request.GET.get('username', '').strip()
    if not username:
        return HttpResponseBadRequest(_('Username is required'))
    user = get_object_or_404(User, username=username)
    return HttpResponseRedirect(reverse('accounts.user-detail', kwargs={'username': user}))


@user_passes_test(lambda u: u.is_superuser)
def user_pending_secrets_csv(request, username):
    user_obj = get_object_or_404(User, username=username)

    pending_qs = get_pending_secrets_for_user(user_obj)

    query = request.GET.get('q')
    if query:
        pending_qs = pending_qs.filter(name__icontains=query)

    # NOTE: If a share was created and then deleted, it is gone from this calculation.
    # It only tracks currently active shares.
    pending_qs = pending_qs.annotate(last_shared=Max('share_data__granted_on'))

    log(
        _('{actor} exported pending secrets CSV for {user}').format(
            actor=request.user.username,
            user=user_obj.username,
        ),
        actor=request.user,
        category=AuditLogCategoryChoices.DATA_EXPORT,
        user=user_obj,
    )

    response = HttpResponse(
        content_type='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{username}_pending_secrets.csv"'},
    )

    writer = csv.writer(response)
    writer.writerow(['Name', 'HashID', 'Type', 'URL', 'Status', 'Last Changed', 'Last Read', 'Last Shared'])

    for secret in pending_qs:
        full_url = request.build_absolute_uri(secret.get_absolute_url())

        last_shared = secret.last_shared.isoformat() if secret.last_shared else ''
        last_changed = secret.last_changed.isoformat() if secret.last_changed else ''
        last_read = secret.last_read.isoformat() if secret.last_read else ''

        writer.writerow([
            secret.name,
            secret.hashid,
            secret.get_content_type_display(),
            full_url,
            secret.get_status_display(),
            last_changed,
            last_read,
            last_shared,
        ])

    return response


@user_passes_test(lambda u: u.is_superuser)
@require_http_methods(['POST'])
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
        accessed_revs = (
            SecretRevision.objects.filter(
                accessed_by=user,
            )
            .exclude(
                secret__needs_changing_on_leave=False,
            )
            .exclude(secret__status=SecretStatus.NEEDS_CHANGING)
            .select_related(
                'secret',
            )
        )
        secrets = set()
        for rev in accessed_revs:
            if rev.is_current_revision:
                secrets.add(rev.secret)
        with transaction.atomic():
            for secret in secrets:
                secret.status = SecretStatus.NEEDS_CHANGING
                secret.save()
                msg = _("secret '{secret}' needs changing because user '{user}' was deactivated").format(
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
            _('{actor} deactivated {user}, {secrets} secrets marked for changing').format(
                actor=request.user.username,
                user=user.username,
                secrets=len(secrets),
            ),
            actor=request.user,
            category=AuditLogCategoryChoices.USER_DEACTIVATED,
            user=user,
        )

        detail_url = reverse('accounts.user-detail', kwargs={'username': user.username})

        pending = get_pending_secrets_for_user(user)
        if pending.exists():
            detail_url = f'{detail_url}?show_pending=1'

    else:
        log(
            _('{actor} reactivated {user}').format(
                actor=request.user.username,
                user=user.username,
            ),
            actor=request.user,
            category=AuditLogCategoryChoices.USER_ACTIVATED,
            user=user,
        )
        detail_url = reverse('accounts.user-detail', kwargs={'username': user.username})

    return HttpResponseRedirect(detail_url)


def search_user(request):
    if not request.user.is_superuser:
        return {}
    q = request.GET.get('q', '').strip()
    if not q:
        return {}
    users_queryset = User.objects.filter(
        Q(username__icontains=q) | Q(first_name__icontains=q) | Q(last_name__icontains=q)
    )[:15]
    results: list[dict[str, str]] = [
        {
            'username': user.username,
            'cn': f'{user.first_name} {user.last_name}'.strip(),
        }
        for user in users_queryset
    ]
    return JsonResponse({'results': results})


def get_user_avatar_partial(request):
    if not request.user.is_superuser:
        return {}
    username = request.GET.get('username', '').strip()
    if not username:
        return {}
    user = User.objects.get(username=username)
    return render(request, 'accounts/_avatar.html', {'user': user, 'tooltip_title': username})
