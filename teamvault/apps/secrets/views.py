from json import dumps, loads
from urllib.parse import quote, urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import Group, User
from django.http import HttpResponse, HttpResponseRedirect, Http404, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.defaultfilters import pluralize
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView, TemplateView
from django.views.generic.edit import CreateView, UpdateView
from django_htmx.http import trigger_client_event

from .filters import SecretFilter
from .forms import CCForm, FileForm, PasswordForm, SecretShareForm
from .models import AccessPermissionTypes, Secret, SharedSecretData
from ..accounts.models import UserSettings
from ..audit.auditlog import log

ACCESS_STR_IDS = {
    'ACCESS_POLICY_ANY': str(Secret.ACCESS_POLICY_ANY),
    'ACCESS_POLICY_DISCOVERABLE': str(Secret.ACCESS_POLICY_DISCOVERABLE),
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


class OpenSearch(TemplateView):
    content_type = "application/xml"
    template_name = "opensearch.xml"

    def get_context_data(self, **kwargs):
        context = super(OpenSearch, self).get_context_data(**kwargs)
        context['base_url'] = settings.BASE_URL
        return context


opensearch = OpenSearch.as_view()


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
        secret.set_data(self.request.user, plaintext_data, skip_access_check=True)

        # Create default share objects
        secret.share_data.create(user=self.request.user)
        try:
            secret.share_data.bulk_create(
                [
                    SharedSecretData(group=group, secret=secret, granted_by=self.request.user)
                    for group in self.request.user.profile.default_sharing_groups.all()
                ]
            )
        except UserSettings.DoesNotExist:
            pass
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

    def get_form(self, form_class=None):
        form = super().get_form(form_class=form_class)
        # handle files with sizes above FILE_UPLOAD_MAX_MEMORY_SIZE setting
        if (
                self.content_type == 'file'
                and self.request.method == 'POST'
                and not self.request.upload_handlers[0].activated
        ):
            form.add_error(
                f'file', f'File size too big. Allowed file size: {settings.FILE_UPLOAD_MAX_MEMORY_SIZE} bytes'
            )
        return form

    def get_template_names(self):
        return "secrets/addedit_content/{}.html".format(self.kwargs['content_type'])


secret_add = login_required(SecretAdd.as_view())


class SecretEdit(UpdateView):
    context_object_name = 'secret'
    slug_field = 'hashid'
    slug_url_kwarg = 'hashid'

    def form_valid(self, form):
        secret = self.object

        for attr in ('access_policy', 'description', 'name', 'needs_changing_on_leave', 'url', 'username'):
            if attr in form.cleaned_data:
                setattr(secret, attr, form.cleaned_data[attr])
        secret.save()

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

    def get_form(self, form_class=None):
        form = super().get_form(form_class=form_class)
        # handle files with sizes above FILE_UPLOAD_MAX_MEMORY_SIZE setting
        if (
                self.content_type == 'file'
                and self.request.method == 'POST'
                and not self.request.upload_handlers[0].activated
        ):
            form.add_error(
                f'file', f'File size too big. Allowed file size: {settings.FILE_UPLOAD_MAX_MEMORY_SIZE} bytes'
            )
        return form

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
        return "secrets/addedit_content/{}.html".format(CONTENT_TYPE_IDENTIFIERS[self.object.content_type])


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
        return HttpResponseRedirect(
            reverse('secrets.secret-list') + "?" + urlencode([("search", secret.name.encode('utf-8'))]))
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
        return HttpResponseRedirect(
            reverse('secrets.secret-list') + "?" + urlencode([("search", secret.name.encode('utf-8'))]))
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
            if context['readable'] == AccessPermissionTypes.SUPERUSER_ALLOWED:
                context['su_access'] = True
        context['show_modal'] = (secret.needs_changing() and (context['readable'] == AccessPermissionTypes.ALLOWED
                                                              or AccessPermissionTypes.SUPERUSER_ALLOWED))
        log(f"context[show_modal]: {context['show_modal']}")
        return context

    def get_object(self, queryset=None):
        object = super(SecretDetail, self).get_object()
        if not object.is_visible_to_user(self.request.user):
            raise Http404
        return object

    def get_template_names(self):
        content_type = CONTENT_TYPE_IDENTIFIERS[self.object.content_type]
        return f'secrets/detail_content/{content_type}.html'


secret_detail = login_required(SecretDetail.as_view())


@login_required
@require_http_methods(["GET"])
def secret_metadata(request, hashid):
    secret = get_object_or_404(Secret, hashid=hashid)
    secret.check_access(request.user)
    share_data = secret.share_data.with_expiry_state().filter(is_expired=False)
    context = {
        'allowed_groups': share_data.groups(),
        'allowed_users': share_data.users(),
        'secret': secret,
    }
    return render(request, context=context, template_name='secrets/detail_content/meta.html')


class SecretList(ListView):
    context_object_name = 'secrets'
    filter = None
    paginate_by = 25
    template_name = "secrets/secret_list.html"

    def get_context_data(self, **kwargs):
        context = super(SecretList, self).get_context_data(**kwargs)
        context['filter'] = self.filter
        context['readable_secrets'] = Secret.get_all_readable_by_user(self.request.user)
        return context

    def get_queryset(self):
        if "search" in self.request.GET:
            queryset = Secret.get_search_results(self.request.user, self.request.GET['search'])
        else:
            queryset = Secret.get_all_visible_to_user(self.request.user)
        self.filter = SecretFilter(self.request.GET, queryset)
        return self.filter.qs


secret_list = login_required(SecretList.as_view())


class SecretShareList(CreateView):
    form_class = SecretShareForm
    slug_field = 'secret__hashid'
    slug_url_kwarg = 'hashid'
    template_name = 'secrets/share_content/share_list_modal.html'

    @cached_property
    def group_shares(self):
        if not self.queryset:
            self.queryset = self.get_queryset().with_expiry_state()
        return self.queryset.groups()

    @cached_property
    def user_shares(self):
        if not self.queryset:
            self.queryset = self.get_queryset()
        return self.queryset.users()

    def get_queryset(self):
        return SharedSecretData.objects.filter(
            secret__hashid=self.kwargs[self.slug_url_kwarg]
        ).prefetch_related('secret', 'user', 'group')

    def get_context_data(self, *, object_list=None, **kwargs):
        secret = get_object_or_404(Secret, hashid=self.kwargs[self.slug_url_kwarg])
        secret.check_access(self.request.user)

        context = {
            'secret': secret,
            'shares': {
                'groups': self.group_shares,
                'users': self.user_shares,
            },
        }
        return super().get_context_data(**context)

    def form_valid(self, form):
        secret = Secret.objects.get(hashid=self.kwargs[self.slug_url_kwarg])
        secret.check_access(self.request.user)
        obj = form.save(commit=False)
        obj.secret = secret
        obj.save()

        log(
            _("{user} granted access to {shared_entity_type} '{name}' {time}").format(
                shared_entity_type=obj.shared_entity_type,
                name=obj.shared_entity_name,
                user=self.request.user.username,
                time=_('until ') + obj.granted_until.isoformat() if obj.granted_until else _('permanently')
            ),
            actor=self.request.user,
            level='warning',
            secret=secret,
        )

        shared_with_object = form.cleaned_data['group'] if form.cleaned_data['group'] else form.cleaned_data['user']
        messages.success(self.request, _('Shared secret with {}'.format(shared_with_object)))

        # Clear cache
        delattr(self, 'group_shares')
        delattr(self, 'user_shares')

        context = self.get_context_data()
        context.update({
            'form': self.get_form_class()(),  # create a new blank form
            'show_object': {
                'id': shared_with_object.id,
                'type': 'group' if form.cleaned_data['group'] else 'user',
            }
        })
        response = self.render_to_response(context=context)
        trigger_client_event(response, 'refreshMetadata')
        return response

    def get_form_class(self):
        form_class = super(SecretShareList, self).get_form_class()

        # Exclude groups and users which the secret was already shared with
        form_class.base_fields['group'].queryset = Group.objects.all().exclude(
            name__in=self.group_shares.values_list('group__name', flat=True)
        ).order_by('name')
        form_class.base_fields['user'].queryset = User.objects.filter(is_active=True).order_by('username').exclude(
            username__in=self.user_shares.values_list('user__username', flat=True)
        ).order_by('username')
        return form_class


secret_share_list = login_required(SecretShareList.as_view())


@login_required
@require_http_methods(['DELETE'])
def secret_share_delete(request, hashid, share_id):
    share_data = get_object_or_404(SharedSecretData, secret__hashid=hashid, id=share_id)
    share_data.secret.check_access(request.user)
    share_data.delete()
    messages.success(
        request,
        _('Successfully removed {} from allowed {}'.format(
            share_data.shared_entity_name, pluralize(share_data.shared_entity_type)
        ))
    )
    response = HttpResponse(status=200)
    trigger_client_event(response, 'refreshMetadata')
    trigger_client_event(response, 'refreshShareData')
    return response


@login_required
@require_http_methods(["GET"])
def secret_search(request):
    search_term = request.GET['q']
    search_limit = request.GET.get('limit', 15)
    search_results = []
    raw_results = Secret.get_search_results(request.user, search_term)
    filtered_secrets = list(raw_results[:search_limit])
    unreadable_secrets = filtered_secrets[:]
    sorted_secrets = []

    # sort readable passwords to top...
    for secret in filtered_secrets:
        if secret.is_readable_by_user(request.user):
            icon = "lock-open"
            metadata = ''
            if secret.content_type == secret.CONTENT_PASSWORD:
                icon = "user"
                metadata = getattr(secret, 'username')
            elif secret.content_type == secret.CONTENT_FILE:
                icon = "file"
                metadata = getattr(secret, 'filename')
            elif secret.content_type == secret.CONTENT_CC:
                icon = "credit-card"
                metadata = getattr(secret, 'description')
            sorted_secrets.append((secret, icon, metadata))
            unreadable_secrets.remove(secret)

    # and others to the bottom
    for secret in unreadable_secrets:
        sorted_secrets.append((secret, "lock"))

    for secret, icon, metadata in sorted_secrets:
        search_results.append({
            'icon': icon,
            'meta': metadata,
            'name': secret.name,
            'url': reverse('secrets.secret-detail', kwargs={'hashid': secret.hashid}),
        })
    return JsonResponse({'count': raw_results.count(), 'results': search_results})
