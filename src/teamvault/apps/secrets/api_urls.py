from django.conf.urls import patterns, url

from .api import AccessRequestDetail, AccessRequestList, SecretDetail, SecretList, \
    SecretRevisionDetail, secret_get


urlpatterns = patterns(
    '',
    url(
        r'^access-requests/$',
        AccessRequestList.as_view(),
        name='api.access-request_list',
    ),
    url(
        r'^access-requests/(?P<pk>\d+)/$',
        AccessRequestDetail.as_view(),
        name='api.access-request_detail',
    ),
    url(
        r'^passwords/$',
        SecretList.as_view(),
        name='api.secret_list',
    ),
    url(
        r'^passwords/(?P<pk>\d+)/$',
        SecretDetail.as_view(),
        name='api.secret_detail',
    ),
    url(
        r'^secret-revisions/(?P<pk>\d+)/$',
        SecretRevisionDetail.as_view(),
        name='api.secret-revision_detail',
    ),
    url(
        r'^secret-revisions/(?P<pk>\d+)/secret$',
        secret_get,
        name='api.secret-revision_secret',
    ),
)
