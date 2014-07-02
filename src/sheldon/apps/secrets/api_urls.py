from django.conf.urls import patterns, url

from .api import PasswordDetail, PasswordList, secret_get


urlpatterns = patterns(
    '',
    url(
        r'^passwords/$',
        PasswordList.as_view(),
        name='api.password_list',
    ),
    url(
        r'^passwords/(?P<id_token>\w+)/$',
        PasswordDetail.as_view(),
        name='api.password_detail',
    ),
    url(
        r'^passwords/(?P<id_token>\w+)/secret$',
        secret_get,
        name='api.password_secret',
    ),
)
