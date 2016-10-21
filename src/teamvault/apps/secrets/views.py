from json import dumps, loads
from urllib.parse import quote, urlencode

from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import Group, User
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import get_object_or_404, render
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, UpdateView

from ..audit.auditlog import log
from .forms import CCForm, FileForm, PasswordForm
from .models import AccessRequest, Secret

ACCESS_STR_IDS = {
    'ACCESS_POLICY_ANY': str(Secret.ACCESS_POLICY_ANY),
    'ACCESS_POLICY_REQUEST': str(Secret.ACCESS_POLICY_REQUEST),
    'ACCESS_POLICY_HIDDEN': str(Secret.ACCESS_POLICY_HIDDEN),
}
CONTENT_TYPE_FORMS = {
    'cc': CCForm,
    'file': FileForm,
    'password': PasswordForm,
}
CONTENT_TYPE_IDS = {
    'cc': Secret.CONTENT_CC,
    'file': Secret.CONTENT_FILE,
    'password': Secret.CONTENT_PASSWORD,
}
CONTENT_TYPE_IDENTIFIERS = {v: k for k, v in CONTENT_TYPE_IDS.items()}
_CONTENT_TYPES = dict(Secret.CONTENT_CHOICES)
CONTENT_TYPE_NAMES = {
    'cc': _CONTENT_TYPES[Secret.CONTENT_CC],
    'file': _CONTENT_TYPES[Secret.CONTENT_FILE],
    'password': _CONTENT_TYPES[Secret.CONTENT_PASSWORD],
}


def _patch_post_data(POST, fields):
    """
    Select2 passes in selected values as CSV instead of as a real
    multiple value field, so we need to split them before any validation
    takes place.
    """
    POST = POST.copy()
    for csv_field in fields:
        if POST.getlist(csv_field) == ['']:
            del POST[csv_field]
        else:
            POST.setlist(
                csv_field,
                POST.getlist(csv_field)[0].split(","),
            )
    return POST


@login_required
def access_request_create(request, hashid):
    secret = Secret.objects.get(hashid=hashid)
    if not secret.is_visible_to_user(request.user):
        raise Http404
    try:
        AccessRequest.objects.get(
            requester=request.user,
            secret=secret,
            status=AccessRequest.STATUS_PENDING,
        )
    except AccessRequest.DoesNotExist:
        if request.method == 'POST' and not secret.is_readable_by_user(request.user):
            access_request = AccessRequest()
            access_request.reason_request = request.POST['reason']
            access_request.requester = request.user
            access_request.secret = secret
            access_request.save()
            access_request.assign_reviewers()
    return HttpResponseRedirect(secret.get_absolute_url())


@login_required
@require_http_methods(["POST"])
def access_request_review(request, hashid, action):
    access_request = get_object_or_404(
        AccessRequest,
        hashid=hashid,
        status=AccessRequest.STATUS_PENDING,
    )
    if not request.user.is_superuser and request.user not in access_request.reviewers.all():
        raise PermissionDenied()

    if action == 'allow':
        access_request.approve(request.user)
    else:
        access_request.reject(request.user, reason=request.POST.get('reason', None))

    return HttpResponseRedirect(reverse('secrets.access_request-list'))


class AccessRequestDetail(DetailView):
    context_object_name = 'access_request'
    model = AccessRequest
    slug_field = 'hashid'
    slug_url_kwarg = 'hashid'
    template_name = "secrets/accessrequest_detail.html"

    def get_object(self):
        if self.request.user.is_superuser:
            return get_object_or_404(
                AccessRequest,
                hashid=self.kwargs['hashid'],
                status=AccessRequest.STATUS_PENDING,
            )
        else:
            return get_object_or_404(
                AccessRequest,
                hashid=self.kwargs['hashid'],
                reviewers=self.request.user,
                status=AccessRequest.STATUS_PENDING,
            )
access_request_detail = login_required(AccessRequestDetail.as_view())


class AccessRequestList(ListView):
    context_object_name = 'access_requests'
    template_name = "secrets/accessrequests_list.html"

    def get_context_data(self, **kwargs):
        queryset = self.get_queryset()
        context = super(AccessRequestList, self).get_context_data(**kwargs)
        context['reviewable'] = queryset.exclude(requester=self.request.user)
        context['pending_review'] = queryset.filter(requester=self.request.user)
        return context

    def get_queryset(self):
        queryset = AccessRequest.get_all_readable_by_user(self.request.user)
        return queryset.filter(status=AccessRequest.STATUS_PENDING)
access_request_list = login_required(AccessRequestList.as_view())


class Dashboard(TemplateView):
    template_name = "secrets/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super(Dashboard, self).get_context_data(**kwargs)
        context['search_term'] = ""
        context['most_used_secrets'] = Secret.get_most_used_for_user(self.request.user)
        context['readable_secrets'] = Secret.get_all_readable_by_user(self.request.user)
        context['recently_used_secrets'] = Secret.get_most_recently_used_for_user(self.request.user)
        return context
dashboard = login_required(Dashboard.as_view())


class SecretAdd(CreateView):
    slug_field = 'hashid'
    slug_url_kwarg = 'hashid'

    def form_valid(self, form):
        secret = Secret()
        secret.content_type = CONTENT_TYPE_IDS[self.kwargs['content_type']]
        secret.created_by = self.request.user

        for attr in ('access_policy', 'description', 'name', 'needs_changing_on_leave', 'url',
                     'username'):
            if attr in form.cleaned_data:
                setattr(secret, attr, form.cleaned_data[attr])
        secret.save()

        for attr in ('allowed_groups', 'allowed_users', 'owner_groups', 'owner_users'):
            setattr(secret, attr, form.cleaned_data[attr])

        if secret.content_type == Secret.CONTENT_PASSWORD:
            plaintext_data = form.cleaned_data['password']
        elif secret.content_type == Secret.CONTENT_FILE:
            plaintext_data = form.cleaned_data['file'].read()
            secret.filename = form.cleaned_data['file'].name
            secret.save()
        elif secret.content_type == Secret.CONTENT_CC:
            plaintext_data = dumps({
                'holder': form.cleaned_data['holder'],
                'number': form.cleaned_data['number'],
                'expiration_month': str(form.cleaned_data['expiration_month']),
                'expiration_year': str(form.cleaned_data['expiration_year']),
                'security_code': str(form.cleaned_data['security_code']),
                'password': form.cleaned_data['password'],
            })
        secret.set_data(self.request.user, plaintext_data)

        return HttpResponseRedirect(secret.get_absolute_url())

    def get_context_data(self, **kwargs):
        context = super(SecretAdd, self).get_context_data(**kwargs)
        try:
            context['pretty_content_type'] = CONTENT_TYPE_NAMES[self.kwargs['content_type']]
        except KeyError:
            raise Http404
        context.update(ACCESS_STR_IDS)
        return context

    def get_form_class(self):
        return CONTENT_TYPE_FORMS[self.kwargs['content_type']]

    def get_template_names(self):
        return "secrets/secret_addedit_{}.html".format(self.kwargs['content_type'])

    def post(self, request, *args, **kwargs):
        request.POST = _patch_post_data(
            request.POST,
            (
                'allowed_groups',
                'allowed_users',
                'owner_groups',
                'owner_users',
            ),
        )
        return super(SecretAdd, self).post(request, *args, **kwargs)
secret_add = login_required(SecretAdd.as_view())


class SecretEdit(UpdateView):
    context_object_name = 'secret'
    slug_field = 'hashid'
    slug_url_kwarg = 'hashid'

    def form_valid(self, form):
        secret = self.object

        for attr in ('access_policy', 'description', 'name', 'needs_changing_on_leave', 'url',
                     'username'):
            if attr in form.cleaned_data:
                setattr(secret, attr, form.cleaned_data[attr])
        secret.save()

        for attr in ('allowed_groups', 'allowed_users', 'owner_groups', 'owner_users'):
            setattr(secret, attr, form.cleaned_data[attr])

        if secret.content_type == Secret.CONTENT_PASSWORD and form.cleaned_data['password']:
            plaintext_data = form.cleaned_data['password']
        elif secret.content_type == Secret.CONTENT_FILE and form.cleaned_data['file']:
            plaintext_data = form.cleaned_data['file'].read()
            secret.filename = form.cleaned_data['file'].name
            secret.save()
        elif secret.content_type == Secret.CONTENT_CC:
            plaintext_data = dumps({
                'holder': form.cleaned_data['holder'],
                'number': form.cleaned_data['number'],
                'expiration_month': form.cleaned_data['expiration_month'],
                'expiration_year': form.cleaned_data['expiration_year'],
                'security_code': form.cleaned_data['security_code'],
                'password': form.cleaned_data['password'],
            })
        else:
            plaintext_data = None

        if plaintext_data is not None:
            secret.set_data(self.request.user, plaintext_data)

        return HttpResponseRedirect(secret.get_absolute_url())

    def get_context_data(self, **kwargs):
        context = super(SecretEdit, self).get_context_data(**kwargs)
        context['pretty_content_type'] = self.object.get_content_type_display()
        context.update(ACCESS_STR_IDS)
        return context

    def get_form_class(self):
        return CONTENT_TYPE_FORMS[CONTENT_TYPE_IDENTIFIERS[self.object.content_type]]

    def get_initial(self):
        if self.object.content_type == Secret.CONTENT_CC:
            data = loads(self.object.get_data(self.request.user))
            return {
                'holder': data['holder'],
                'number': data['number'],
                'expiration_month': data['expiration_month'],
                'expiration_year': data['expiration_year'],
                'security_code': data['security_code'],
                'password': data['password'],
            }
        else:
            return {}

    def get_object(self, queryset=None):
        secret = get_object_or_404(Secret, hashid=self.kwargs['hashid'])
        secret.check_access(self.request.user)
        return secret

    def get_template_names(self):
        return "secrets/secret_addedit_{}.html".format(CONTENT_TYPE_IDENTIFIERS[self.object.content_type])

    def post(self, request, *args, **kwargs):
        request.POST = _patch_post_data(
            request.POST,
            (
                'allowed_groups',
                'allowed_users',
                'owner_groups',
                'owner_users',
            ),
        )
        return super(SecretEdit, self).post(request, *args, **kwargs)
secret_edit = login_required(SecretEdit.as_view())


@login_required
def secret_delete(request, hashid):
    secret = get_object_or_404(Secret, hashid=hashid)
    secret.check_access(request.user)
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
        return render(request, "secrets/secret_delete.html", {'secret': secret})


@login_required
@user_passes_test(lambda u: u.is_superuser)
def secret_restore(request, hashid):
    secret = get_object_or_404(Secret, hashid=hashid)
    secret.check_access(request.user)
    if request.method == 'POST':
        log(_(
                "{user} restore '{name}' ({id}:{revision})"
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
        secret.status = Secret.STATUS_OK
        secret.save()
        return HttpResponseRedirect(reverse('secrets.secret-list') + "?" + urlencode([("search", secret.name.encode('utf-8'))]))
    else:
        return render(request, "secrets/secret_restore.html", {'secret': secret})


@login_required
@require_http_methods(["GET"])
def secret_download(request, hashid):
    secret = get_object_or_404(Secret, hashid=hashid)
    if secret.content_type != Secret.CONTENT_FILE:
        raise Http404
    secret.check_access(request.user)

    response = HttpResponse(secret.get_data(request.user))
    response['Content-Disposition'] = \
        "attachment; filename*=UTF-8''{}".format(quote(secret.filename))
    response['Content-Type'] = "application/force-download"
    return response


class SecretDetail(DetailView):
    context_object_name = 'secret'
    model = Secret
    slug_field = 'hashid'
    slug_url_kwarg = 'hashid'
    template_name = "secrets/secret_detail.html"

    def get_context_data(self, **kwargs):
        context = super(SecretDetail, self).get_context_data(**kwargs)
        secret = self.get_object()
        context['content_type'] = CONTENT_TYPE_IDENTIFIERS[secret.content_type]
        context['readable'] = secret.is_readable_by_user(self.request.user)
        context['secret_url'] = reverse(
            'api.secret-revision_data',
            kwargs={'hashid': secret.current_revision.hashid},
        )
        if context['readable']:
            context['placeholder'] = secret.current_revision.length * "•"
        else:
            try:
                context['access_request'] = AccessRequest.objects.get(
                    secret=secret,
                    status=AccessRequest.STATUS_PENDING,
                    requester=self.request.user,
                )
            except AccessRequest.DoesNotExist:
                context['access_request'] = None
        return context

    def get_object(self):
        object = super(SecretDetail, self).get_object()
        if not object.is_visible_to_user(self.request.user):
            raise Http404
        return object
secret_detail = login_required(SecretDetail.as_view())


class SecretList(ListView):
    context_object_name = 'secrets'
    paginate_by = 25
    template_name = "secrets/secret_list.html"

    def get_context_data(self, **kwargs):
        context = super(SecretList, self).get_context_data(**kwargs)
        context['readable_secrets'] = Secret.get_all_readable_by_user(self.request.user)
        context['search_term'] = self.request.GET.get('search', None)
        context['search_term_url'] = quote(self.request.GET.get('search', ""))
        return context

    def get_queryset(self):
        if "search" in self.request.GET:
            return Secret.get_search_results(self.request.user, self.request.GET['search'])
        else:
            return Secret.get_all_visible_to_user(self.request.user)
secret_list = login_required(SecretList.as_view())


@login_required
@require_http_methods(["POST"])
def secret_share(request, hashid):
    secret = get_object_or_404(Secret, hashid=hashid)
    secret.check_access(request.user)

    request.POST = _patch_post_data(request.POST, ('share_groups', 'share_users'))

    groups = []
    for group_id in request.POST.getlist('share_groups', []):
        groups.append(get_object_or_404(Group, pk=int(group_id)))

    users = []
    for user_id in request.POST.getlist('share_users', []):
        users.append(get_object_or_404(User, pk=int(user_id)))

    for group in groups:
        log(
            _("{actor} shared '{secret}' with {group}").format(
                actor=request.user,
                group=group.name,
                secret=secret.name,
            ),
            actor=request.user,
            group=group,
            secret=secret,
        )
        secret.allowed_groups.add(group)
        # TODO email with additional message field

    for user in users:
        log(
            _("{actor} shared '{secret}' with {user}").format(
                actor=request.user,
                secret=secret.name,
                user=user.username,
            ),
            actor=request.user,
            secret=secret,
            user=user,
        )
        secret.allowed_users.add(user)
        # TODO email with additional message field

    return HttpResponseRedirect(secret.get_absolute_url())


@login_required
@require_http_methods(["GET"])
def secret_search(request):
    search_term = request.GET['q']
    search_result = []
    filtered_secrets = Secret.get_search_results(request.user, search_term, limit=10)
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
            'url': reverse('secrets.secret-detail', kwargs={'hashid': secret.hashid}),
            'icon': icon,
        })

    return HttpResponse(dumps(search_result), content_type="application/json")
