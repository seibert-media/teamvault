from django.conf.urls import patterns, url

from .api import PasswordList


urlpatterns = patterns(
    '',
    url(
        r'^passwords/$',
        PasswordList.as_view(),
        name='api.password_list',
    ),
)
