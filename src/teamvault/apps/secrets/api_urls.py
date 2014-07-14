from django.conf.urls import patterns, url

from .api import AccessRequestDetail, AccessRequestList, PasswordDetail, PasswordList, \
    PasswordRevisionDetail, secret_get


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
        PasswordList.as_view(),
        name='api.password_list',
    ),
    url(
        r'^passwords/(?P<pk>\d+)/$',
        PasswordDetail.as_view(),
        name='api.password_detail',
    ),
    url(
        r'^password-revisions/(?P<pk>\d+)/$',
        PasswordRevisionDetail.as_view(),
        name='api.password-revision_detail',
    ),
    url(
        r'^password-revisions/(?P<pk>\d+)/secret$',
        secret_get,
        name='api.password-revision_secret',
    ),
)
