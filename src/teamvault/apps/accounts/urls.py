from django.conf.urls import patterns, url
from django.contrib import admin
from django.contrib.auth.views import login, logout


admin.autodiscover()

urlpatterns = patterns(
    '',
    url(
        r'^login$',
        login,
        {'template_name': "accounts/login.html"},
        name='accounts.login',
    ),
    url(
        r'^logout$',
        logout,
        {'template_name': "accounts/logout.html"},
        name='accounts.logout',
    ),
)
