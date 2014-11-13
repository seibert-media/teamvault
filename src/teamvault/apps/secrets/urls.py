from django.conf.urls import patterns, url
from django.contrib.auth.decorators import login_required
from django.views.generic import TemplateView

from .views import live_search, SecretAdd, SecretEdit, secret_delete, SecretDetail, SecretList

urlpatterns = patterns('',
    url(
        r'^$',
        login_required(TemplateView.as_view(template_name="secrets/dashboard.html")),
        name='dashboard',
    ),
    url(
        r'^secrets/$',
        login_required(SecretList.as_view()),
        name='secrets.secret-list',
    ),
    url(
        r'^secrets/(?P<pk>\d+)$',
        login_required(SecretDetail.as_view()),
        name='secrets.secret-detail',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/delete$',
        secret_delete,
        name='secrets.secret-delete',
    ),
    url(
        r'^secrets/(?P<pk>\d+)/edit$',
        login_required(SecretEdit.as_view()),
        name='secrets.secret-edit',
    ),
    url(
        r'^secrets/add/(?P<content_type>\w+)$',
        login_required(SecretAdd.as_view()),
        name='secrets.secret-add',
    ),
    url(
        r'^secrets/live-search$',
        live_search,
        name='secrets.live-search',
    ),
)
