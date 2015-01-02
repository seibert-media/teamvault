from django.conf.urls import patterns, url
from django.contrib.auth.decorators import login_required
from django.views.generic import TemplateView

from . import views

urlpatterns = patterns('',
    url(
        r'^$',
        login_required(TemplateView.as_view(template_name="secrets/dashboard.html")),
        name='dashboard',
    ),
    url(
        r'^access_requests/$',
        login_required(views.AccessRequestList.as_view()),
        name='secrets.access_request-list',
    ),
    url(
        r'^access_requests/(?P<pk>\d+)$',
        login_required(views.AccessRequestDetail.as_view()),
        name='secrets.access_request-detail',
    ),
    url(
        r'^access_requests/(?P<pk>\d+)/(?P<action>(allow|deny))$',
        views.access_request_review,
        name='secrets.access_request-review',
    ),
    url(
        r'^secrets/$',
        login_required(views.SecretList.as_view()),
        name='secrets.secret-list',
    ),
    url(
        r'^secrets/(?P<pk>\d+)$',
        login_required(views.SecretDetail.as_view()),
        name='secrets.secret-detail',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/delete$',
        views.secret_delete,
        name='secrets.secret-delete',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/download$',
        views.secret_download,
        name='secrets.secret-download',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/edit$',
        login_required(views.SecretEdit.as_view()),
        name='secrets.secret-edit',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/request_access$',
        views.access_request_create,
        name='secrets.secret-request_access',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/share$',
        views.secret_share,
        name='secrets.secret-share',
    ),
    url(
        r'^secrets/add/(?P<content_type>\w+)$',
        login_required(views.SecretAdd.as_view()),
        name='secrets.secret-add',
    ),
    url(
        r'^secrets/search$',
        views.secret_search,
        name='secrets.secret-search',
    ),
)
